"""Evaluator agent: rule-based SSVC scoring and scope gate. No LLM needed."""
import logging
from src.agents.state import AutopatchState

logger = logging.getLogger(__name__)

CRITICALITY_WEIGHTS = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}

def compute_ssvc_decision(cvss: float | None, epss: float | None, is_kev: bool, criticality: str) -> str:
    cvss = cvss or 0.0
    epss = epss or 0.0
    if is_kev or epss >= 0.7:
        return "act"
    if cvss >= 9.0 and criticality == "critical":
        return "act"
    if cvss >= 7.0 or epss >= 0.3:
        return "attend"
    if cvss >= 4.0:
        return "track*"
    return "track"

def compute_priority_score(cvss: float | None, epss: float | None, is_kev: bool, criticality: str) -> float:
    cvss = cvss or 0.0
    epss = epss or 0.0
    kev_weight = 1.0 if is_kev else 0.0
    crit_weight = CRITICALITY_WEIGHTS.get(criticality, 0.5)
    score = (cvss / 10.0 * 40) + (epss * 35) + (kev_weight * 15) + (crit_weight * 10)
    return round(score, 1)

def evaluator_node(state: AutopatchState) -> dict:
    scan_data = state.get("scan_data", {})
    cvss = scan_data.get("cvss_score")
    epss = scan_data.get("epss_score")
    is_kev = scan_data.get("is_kev", False)
    criticality = scan_data.get("asset_criticality", "medium")
    ssvc = compute_ssvc_decision(cvss, epss, is_kev, criticality)
    priority = compute_priority_score(cvss, epss, is_kev, criticality)
    in_scope = ssvc in ("act", "attend")
    scope_decision = "in_scope" if in_scope else "out_of_scope"
    scope_reason = f"SSVC={ssvc}, CVSS={cvss}, EPSS={epss}, KEV={is_kev}, criticality={criticality}"
    logger.info("Evaluator: vuln=%s scope=%s ssvc=%s priority=%.1f", state["vulnerability_id"], scope_decision, ssvc, priority)
    return {
        "cvss_score": cvss, "epss_score": epss, "is_kev": is_kev,
        "ssvc_decision": ssvc, "priority_score": priority,
        "scope_decision": scope_decision, "scope_reason": scope_reason,
        "status": "evaluating" if in_scope else "out_of_scope",
    }
