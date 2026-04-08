"""Shared state schema for the Autopatch LangGraph workflow."""

from typing import TypedDict


class AutopatchState(TypedDict):
    # Input
    vulnerability_id: str
    asset_id: str
    cve_id: str | None
    scan_data: dict

    # Enrichment (from evaluator)
    epss_score: float | None
    is_kev: bool
    cvss_score: float | None
    ssvc_decision: str | None       # track / track* / attend / act
    priority_score: float | None
    scope_decision: str             # pending / in_scope / out_of_scope
    scope_reason: str
    asset_criticality: str          # low / medium / high / critical

    # Research results (from research agent)
    cve_details: dict | None
    vendor_advisories: list[str]
    references: list[str]

    # Docs results (from docs agent)
    doc_chunks: list[str]
    doc_sources: list[str]

    # Lead agent output
    remediation_plan: dict | None
    strategy: str | None            # vendor_patch / config_workaround / compensating_control

    # Control
    status: str                     # pending / evaluating / researching / planning / complete / out_of_scope / error
    error: str | None


def make_initial_state(
    vulnerability_id: str,
    asset_id: str,
    cve_id: str | None,
    scan_data: dict,
    asset_criticality: str = "medium",
) -> AutopatchState:
    return AutopatchState(
        vulnerability_id=vulnerability_id,
        asset_id=asset_id,
        cve_id=cve_id,
        scan_data=scan_data,
        epss_score=None,
        is_kev=False,
        cvss_score=None,
        ssvc_decision=None,
        priority_score=None,
        scope_decision="pending",
        scope_reason="",
        asset_criticality=asset_criticality,
        cve_details=None,
        vendor_advisories=[],
        references=[],
        doc_chunks=[],
        doc_sources=[],
        remediation_plan=None,
        strategy=None,
        status="pending",
        error=None,
    )
