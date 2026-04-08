"""Enrich vulnerability data with EPSS/KEV/CVSS from cve_enrichment table."""
import logging
from sqlalchemy import select
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def enrich_vuln_dicts(vuln_dicts: list[dict], enrichment_data: dict) -> list[dict]:
    """Enrich vuln dicts in-place using pre-fetched enrichment_data map.
    enrichment_data: {cve_id: {epss_score, epss_percentile, is_kev, cvss_v3_score}}
    """
    for vd in vuln_dicts:
        cve_ids = vd.get("cve_ids", [])
        for cve_id in cve_ids:
            enrichment = enrichment_data.get(cve_id)
            if enrichment:
                vd["epss_score"] = enrichment.get("epss_score")
                vd["epss_percentile"] = enrichment.get("epss_percentile")
                vd["is_kev"] = enrichment.get("is_kev", False)
                if vd.get("cvss_score") is None and enrichment.get("cvss_v3_score"):
                    vd["cvss_score"] = enrichment["cvss_v3_score"]
                break
    return vuln_dicts


def fetch_enrichment_for_cves(session: Session, cve_ids: list[str]) -> dict:
    """Batch-fetch enrichment data for a list of CVE IDs. Returns {cve_id: dict}."""
    if not cve_ids:
        return {}
    from src.api.models.cve_enrichment import CVEEnrichment
    result = session.execute(
        select(CVEEnrichment).where(CVEEnrichment.cve_id.in_(cve_ids))
    )
    enrichment_map = {}
    for row in result.scalars():
        enrichment_map[row.cve_id] = {
            "epss_score": float(row.epss_score) if row.epss_score is not None else None,
            "epss_percentile": float(row.epss_percentile) if row.epss_percentile is not None else None,
            "is_kev": row.is_kev,
            "cvss_v3_score": float(row.cvss_v3_score) if row.cvss_v3_score is not None else None,
        }
    return enrichment_map


def re_enrich_open(session: Session) -> int:
    """Re-enrich all open vulnerabilities from cve_enrichment. Returns count updated."""
    from src.api.models.vulnerability import Vulnerability
    result = session.execute(
        select(Vulnerability).where(Vulnerability.status == "open", Vulnerability.cve_id.is_not(None))
    )
    vulns = result.scalars().all()
    if not vulns:
        return 0
    cve_ids = list({v.cve_id for v in vulns if v.cve_id})
    enrichment_map = fetch_enrichment_for_cves(session, cve_ids)
    count = 0
    for v in vulns:
        e = enrichment_map.get(v.cve_id)
        if not e:
            continue
        changed = False
        if e["epss_score"] is not None and v.epss_score != e["epss_score"]:
            v.epss_score = e["epss_score"]
            changed = True
        if e["epss_percentile"] is not None and v.epss_percentile != e["epss_percentile"]:
            v.epss_percentile = e["epss_percentile"]
            changed = True
        if e["is_kev"] != v.is_kev:
            v.is_kev = e["is_kev"]
            changed = True
        if changed:
            count += 1
    session.commit()
    logger.info("Re-enriched %d open vulnerabilities", count)
    return count
