"""Shared agent state schema for the Autopatch LangGraph workflow."""
from typing import TypedDict

class AutopatchState(TypedDict):
    vulnerability_id: str
    asset_id: str
    cve_id: str | None
    scan_data: dict
    epss_score: float | None
    is_kev: bool
    cvss_score: float | None
    ssvc_decision: str | None
    priority_score: float | None
    scope_decision: str
    scope_reason: str
    cve_details: dict | None
    vendor_advisories: list[str]
    references: list[str]
    doc_chunks: list[str]
    doc_sources: list[str]
    status: str
    error: str | None

def make_initial_state(vulnerability_id: str, asset_id: str, cve_id: str | None, scan_data: dict) -> AutopatchState:
    return AutopatchState(
        vulnerability_id=vulnerability_id, asset_id=asset_id,
        cve_id=cve_id, scan_data=scan_data,
        epss_score=None, is_kev=False, cvss_score=None,
        ssvc_decision=None, priority_score=None,
        scope_decision="pending", scope_reason="",
        cve_details=None, vendor_advisories=[], references=[],
        doc_chunks=[], doc_sources=[],
        status="pending", error=None,
    )
