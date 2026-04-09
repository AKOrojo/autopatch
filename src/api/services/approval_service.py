"""Approval gate evaluation logic."""


def evaluate_approval(
    cvss_score: float | None,
    remediation_type: str,
    asset_tier: str,
    policy: dict,
    global_mode: str,
) -> dict:
    if global_mode == "manual":
        return {"auto_approved": False, "reasons": ["Global mode is manual"]}

    reasons = []
    cvss = cvss_score or 0.0

    if cvss > policy.get("max_auto_approve_cvss", 7.0):
        reasons.append(f"CVSS {cvss} exceeds threshold {policy['max_auto_approve_cvss']}")

    if policy.get("auto_approve_config_only", False) and remediation_type != "config_only":
        reasons.append(f"Remediation type '{remediation_type}' is not config-only")

    if policy.get("require_approval_for_service_restart", True) and remediation_type == "service_restart":
        reasons.append("Service restart requires approval")

    return {"auto_approved": len(reasons) == 0, "reasons": reasons}
