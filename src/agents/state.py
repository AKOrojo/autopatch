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

    # Execution (from executor agent)
    execution_result: dict | None   # pre_commands, playbook, post_commands results

    # Control
    status: str                     # pending / evaluating / researching / planning / executing / executed / complete / out_of_scope / error
    error: str | None

    # Approval gate
    asset_tier: str                     # dev / staging / prod
    approval_status: str                # pending / approved / waiting / rejected
    approval_auto_approved: bool
    approval_policy: dict | None        # loaded from DB at task start
    global_mode: str                    # auto / manual
    approval_request_id: str | None     # UUID of the approval_requests row

    # Verification (from verification agent)
    verification_results: dict | None
    pre_services: list[str]

    # Retry / circuit breaker
    strategy_history: list[dict]            # [{strategy, attempt, error, commands, duration}]
    current_strategy_index: int             # 0=vendor_patch, 1=config_workaround, 2=compensating_control
    attempt_within_strategy: int            # 1 or 2 (max 2 per strategy)
    total_attempts: int                     # across all strategies
    remediation_started_at: str | None      # ISO timestamp for global timeout

    # Dead letter
    dead_letter_reason: str | None
    artifact_bundle_path: str | None


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
        execution_result=None,
        status="pending",
        error=None,
        verification_results=None,
        pre_services=[],
        strategy_history=[],
        current_strategy_index=0,
        attempt_within_strategy=1,
        total_attempts=0,
        remediation_started_at=None,
        dead_letter_reason=None,
        artifact_bundle_path=None,
        asset_tier="dev",
        approval_status="pending",
        approval_auto_approved=False,
        approval_policy=None,
        global_mode="auto",
        approval_request_id=None,
    )
