"""Celery tasks for scan lifecycle: run, ingest results, poll OpenVAS."""
import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import create_engine, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from src.workers.celery_app import celery_app
from src.api.config import Settings
from src.api.services.scanner_service import get_scanner_backend

logger = logging.getLogger(__name__)

settings = Settings()


# ---------------------------------------------------------------------------
# DB helpers (synchronous — Celery workers are sync by default)
# ---------------------------------------------------------------------------

def _get_db_session() -> Session:
    """Return a synchronous SQLAlchemy Session."""
    sync_url = settings.database_url.replace("postgresql+asyncpg", "postgresql")
    engine = create_engine(sync_url)
    return Session(engine)


def _get_scan(scan_id: str) -> dict:
    """Query Scan + Asset, return plain dict."""
    from src.api.models.scan import Scan
    from src.api.models.asset import Asset

    with _get_db_session() as session:
        result = (
            session.execute(
                select(Scan, Asset)
                .join(Asset, Scan.asset_id == Asset.id)
                .where(Scan.id == scan_id)
            )
            .one()
        )
        scan, asset = result
        return {
            "id": str(scan.id),
            "asset_id": str(scan.asset_id),
            "scanner_type": scan.scanner_type,
            "status": scan.status,
            "scanner_task_id": scan.scanner_task_id,
            "config": scan.config or {},
            "report_id": str(scan.report_id) if scan.report_id else None,
            "asset_ip": asset.ip_address,
        }


def _update_scan(scan_id: str, **kwargs) -> None:
    """Update fields on the Scan row."""
    from src.api.models.scan import Scan

    with _get_db_session() as session:
        session.execute(update(Scan).where(Scan.id == scan_id).values(**kwargs))
        session.commit()


def _create_vulnerabilities(vuln_dicts: list[dict], scan_id: str, asset_id: str, report_id: str | None = None) -> None:
    """Persist Vulnerability records with CVE dedup (upsert on asset_id+cve_id)."""
    from src.api.models.vulnerability import Vulnerability

    rows: list[dict] = []
    for v in vuln_dicts:
        cve_ids = v.get("cve_ids") or []
        base = dict(
            scan_id=scan_id,
            asset_id=asset_id,
            report_id=report_id,
            cwe_id=v.get("cwe_id"),
            title=v.get("title", "Unknown"),
            description=v.get("description"),
            severity=v.get("severity", "unknown"),
            cvss_score=v.get("cvss_score"),
            epss_score=v.get("epss_score"),
            epss_percentile=v.get("epss_percentile"),
            is_kev=v.get("is_kev", False),
            affected_package=v.get("affected_package"),
            affected_version=v.get("affected_version"),
            fixed_version=v.get("fixed_version"),
        )
        if cve_ids:
            for cve in cve_ids:
                rows.append({**base, "cve_id": cve})
        else:
            rows.append({**base, "cve_id": None})

    if not rows:
        return

    # Fields to update when a duplicate (asset_id, cve_id) is found
    update_fields = [
        "scan_id", "cwe_id", "title", "description", "severity",
        "cvss_score", "epss_score", "epss_percentile", "is_kev",
        "affected_package", "affected_version", "fixed_version",
    ]

    with _get_db_session() as session:
        # Rows WITH a cve_id get upserted (deduped per asset)
        cve_rows = [r for r in rows if r.get("cve_id")]
        nocve_rows = [r for r in rows if not r.get("cve_id")]

        if cve_rows:
            stmt = pg_insert(Vulnerability).values(cve_rows)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_vuln_report_asset_cve",
                set_={f: stmt.excluded[f] for f in update_fields},
            )
            session.execute(stmt)

        # Rows without CVE IDs are always inserted (can't dedup without an ID)
        for r in nocve_rows:
            session.add(Vulnerability(**r))

        session.commit()


# ---------------------------------------------------------------------------
# Core async implementations
# ---------------------------------------------------------------------------

def _check_report_completion(report_id: str) -> None:
    """If all scans in a report are done, mark the report as completed."""
    from src.api.models.scan import Scan
    from src.api.models.scan_report import ScanReport
    from src.api.models.vulnerability import Vulnerability

    with _get_db_session() as session:
        scans = session.execute(
            select(Scan).where(Scan.report_id == report_id)
        ).scalars().all()

        if all(s.status in ("completed", "failed") for s in scans):
            total_vulns = session.execute(
                select(func.count(Vulnerability.id)).where(Vulnerability.report_id == report_id)
            ).scalar() or 0

            overall_status = "completed" if any(s.status == "completed" for s in scans) else "failed"
            session.execute(
                update(ScanReport).where(ScanReport.id == report_id).values(
                    status=overall_status,
                    total_vulns=total_vulns,
                    completed_at=datetime.now(timezone.utc),
                )
            )
            session.commit()


async def _run_scan_async(scan_id: str) -> None:
    scan = _get_scan(scan_id)
    scanner_type = scan["scanner_type"]
    backend = get_scanner_backend(scanner_type)

    _update_scan(scan_id, status="running", started_at=datetime.now(timezone.utc))

    try:
        scanner_task_id = await backend.start_scan(scan["asset_ip"], scan["config"])
        _update_scan(scan_id, scanner_task_id=scanner_task_id)

        if scanner_type == "openvas":
            webhook_url = (
                f"{settings.webhook_base_url}/api/v1/scans/webhook/openvas"
                f"?scan_id={scan_id}"
            )
            await backend.configure_alert(scanner_task_id, webhook_url)
        else:
            # nuclei / trivy report results synchronously — ingest immediately
            await _ingest_results_async(scan_id)

    except Exception:
        logger.exception("run_scan failed for scan %s", scan_id)
        _update_scan(scan_id, status="failed")
        raise


async def _ingest_results_async(scan_id: str) -> None:
    scan = _get_scan(scan_id)
    backend = get_scanner_backend(scan["scanner_type"])

    results = await backend.get_results(scan["scanner_task_id"])

    # Inline enrichment
    from src.api.services.enrichment_service import enrich_vuln_dicts, fetch_enrichment_for_cves
    all_cve_ids = []
    for r in results:
        all_cve_ids.extend(r.get("cve_ids", []))
    all_cve_ids = list(set(all_cve_ids))
    if all_cve_ids:
        with _get_db_session() as session:
            enrichment_data = fetch_enrichment_for_cves(session, all_cve_ids)
        results = enrich_vuln_dicts(results, enrichment_data)

    _create_vulnerabilities(results, scan_id, scan["asset_id"], scan.get("report_id"))
    _update_scan(
        scan_id,
        status="completed",
        completed_at=datetime.now(timezone.utc),
        vuln_count=len(results),
    )

    if scan.get("report_id"):
        _check_report_completion(scan["report_id"])


async def _poll_openvas_async() -> None:
    from src.api.models.scan import Scan

    with _get_db_session() as session:
        rows = session.execute(
            select(Scan).where(
                Scan.scanner_type == "openvas",
                Scan.status == "running",
            )
        ).scalars().all()

    backend = get_scanner_backend("openvas")

    for scan in rows:
        scan_id = str(scan.id)
        try:
            status = await backend.get_scan_status(scan.scanner_task_id)
            if status == "done":
                await _ingest_results_async(scan_id)
        except Exception:
            logger.exception("poll_openvas failed for scan %s", scan_id)


# ---------------------------------------------------------------------------
# Celery tasks
# ---------------------------------------------------------------------------

@celery_app.task(name="src.workers.scan_tasks.run_scan", bind=True, max_retries=3)
def run_scan(self, scan_id: str) -> None:
    """Trigger a scan via the appropriate backend."""
    asyncio.get_event_loop().run_until_complete(_run_scan_async(scan_id))


@celery_app.task(name="src.workers.scan_tasks.ingest_results", bind=True, max_retries=3)
def ingest_results(self, scan_id: str) -> None:
    """Fetch results from the backend and persist vulnerabilities."""
    asyncio.get_event_loop().run_until_complete(_ingest_results_async(scan_id))


@celery_app.task(name="src.workers.scan_tasks.poll_openvas_scans")
def poll_openvas_scans() -> None:
    """Beat task: check all running OpenVAS scans for completion."""
    asyncio.get_event_loop().run_until_complete(_poll_openvas_async())
