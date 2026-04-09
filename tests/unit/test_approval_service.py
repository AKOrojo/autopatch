import pytest
from src.api.services.approval_service import evaluate_approval


def test_auto_approve_low_risk_dev():
    result = evaluate_approval(cvss_score=5.0, remediation_type="config_only", asset_tier="dev",
        policy={"max_auto_approve_cvss": 7.0, "auto_approve_config_only": True, "require_approval_for_service_restart": True}, global_mode="auto")
    assert result["auto_approved"] is True


def test_require_approval_high_cvss_prod():
    result = evaluate_approval(cvss_score=9.5, remediation_type="config_only", asset_tier="prod",
        policy={"max_auto_approve_cvss": 7.0, "auto_approve_config_only": True, "require_approval_for_service_restart": True}, global_mode="auto")
    assert result["auto_approved"] is False


def test_require_approval_service_restart():
    result = evaluate_approval(cvss_score=3.0, remediation_type="service_restart", asset_tier="dev",
        policy={"max_auto_approve_cvss": 7.0, "auto_approve_config_only": True, "require_approval_for_service_restart": True}, global_mode="auto")
    assert result["auto_approved"] is False


def test_manual_mode_always_requires_approval():
    result = evaluate_approval(cvss_score=2.0, remediation_type="config_only", asset_tier="dev",
        policy={"max_auto_approve_cvss": 10.0, "auto_approve_config_only": True, "require_approval_for_service_restart": False}, global_mode="manual")
    assert result["auto_approved"] is False


def test_kernel_patch_requires_approval():
    result = evaluate_approval(cvss_score=5.0, remediation_type="kernel_patch", asset_tier="dev",
        policy={"max_auto_approve_cvss": 7.0, "auto_approve_config_only": True, "require_approval_for_service_restart": True}, global_mode="auto")
    assert result["auto_approved"] is False
