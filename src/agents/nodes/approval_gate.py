"""LangGraph node: approval gate between lead and executor."""
import logging
from src.api.services.approval_service import evaluate_approval

logger = logging.getLogger(__name__)


def approval_gate_node(state: dict) -> dict:
    plan = state.get("remediation_plan", {})
    remediation_type = plan.get("remediation_type", "package_update")
    cvss_score = state.get("cvss_score")
    asset_tier = state.get("asset_tier", "dev")
    policy = state.get("approval_policy") or {
        "max_auto_approve_cvss": 7.0, "auto_approve_config_only": True, "require_approval_for_service_restart": True,
    }
    global_mode = state.get("global_mode", "auto")

    result = evaluate_approval(cvss_score=cvss_score, remediation_type=remediation_type, asset_tier=asset_tier, policy=policy, global_mode=global_mode)

    if result["auto_approved"]:
        logger.info("Remediation auto-approved for asset_tier=%s, cvss=%s, type=%s", asset_tier, cvss_score, remediation_type)
        return {"approval_status": "approved", "approval_auto_approved": True}

    logger.info("Remediation requires manual approval: %s", result["reasons"])
    return {"approval_status": "waiting", "approval_auto_approved": False}
