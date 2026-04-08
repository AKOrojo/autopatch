"""NVD lookup tool — reads from cve_enrichment table."""
from sqlalchemy import select
from sqlalchemy.orm import Session

def nvd_lookup(cve_id: str, session: Session) -> dict | None:
    from src.api.models.cve_enrichment import CVEEnrichment
    row = session.execute(
        select(CVEEnrichment).where(CVEEnrichment.cve_id == cve_id)
    ).scalar_one_or_none()
    if row is None:
        return None
    return {
        "cve_id": row.cve_id,
        "description": row.description,
        "cvss_v3_score": float(row.cvss_v3_score) if row.cvss_v3_score else None,
        "cvss_v3_vector": row.cvss_v3_vector,
        "references": row.references or [],
        "affected_configs": row.affected_configs or [],
    }
