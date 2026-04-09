import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Response, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_authenticated
from src.api.models.scan_report import ScanReport
from src.api.models.scan import Scan
from src.api.models.vulnerability import Vulnerability
from src.api.schemas.scan_report import ScanReportCreate, ScanReportResponse
from src.workers.scan_tasks import run_scan

router = APIRouter(prefix="/api/v1/scan-reports", tags=["scan-reports"])


@router.post("", response_model=ScanReportResponse)
async def create_scan_report(
    body: ScanReportCreate,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(get_authenticated),
):
    report = ScanReport(
        asset_id=body.asset_id,
        scanner_types=",".join(body.scanner_types),
        status="running",
    )
    db.add(report)
    await db.flush()

    for scanner_type in body.scanner_types:
        scan = Scan(
            asset_id=body.asset_id,
            report_id=report.id,
            scanner_type=scanner_type,
            status="pending",
        )
        db.add(scan)
        await db.flush()
        run_scan.delay(str(scan.id))

    await db.commit()
    await db.refresh(report)
    return report


@router.get("", response_model=list[ScanReportResponse])
async def list_scan_reports(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(get_authenticated),
    response: Response = None,
):
    total = (await db.execute(select(func.count(ScanReport.id)))).scalar()
    response.headers["X-Total-Count"] = str(total)
    result = await db.execute(
        select(ScanReport).order_by(ScanReport.created_at.desc()).limit(limit).offset(offset)
    )
    return result.scalars().all()


@router.get("/{report_id}")
async def get_scan_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(get_authenticated),
):
    report = (await db.execute(select(ScanReport).where(ScanReport.id == report_id))).scalar_one_or_none()
    if not report:
        raise HTTPException(404, "Report not found")

    scans = (await db.execute(
        select(Scan).where(Scan.report_id == report_id).order_by(Scan.created_at)
    )).scalars().all()

    vulns = (await db.execute(
        select(Vulnerability).where(Vulnerability.report_id == report_id).order_by(Vulnerability.severity)
    )).scalars().all()

    return {
        "id": report.id,
        "asset_id": report.asset_id,
        "status": report.status,
        "scanner_types": report.scanner_types,
        "total_vulns": report.total_vulns,
        "created_at": report.created_at,
        "completed_at": report.completed_at,
        "scans": [
            {
                "id": s.id, "scanner_type": s.scanner_type, "status": s.status,
                "vuln_count": s.vuln_count, "started_at": s.started_at, "completed_at": s.completed_at,
            }
            for s in scans
        ],
        "vulnerabilities": [
            {
                "id": v.id, "cve_id": v.cve_id, "cwe_id": v.cwe_id, "title": v.title,
                "severity": v.severity, "cvss_score": float(v.cvss_score) if v.cvss_score else None,
                "epss_score": float(v.epss_score) if v.epss_score else None,
                "is_kev": v.is_kev, "status": v.status,
                "affected_package": v.affected_package, "fixed_version": v.fixed_version,
                "in_scope": v.status == "open" and v.cve_id is not None,
            }
            for v in vulns
        ],
    }
