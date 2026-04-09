import pytest
from src.agents.nodes.approval_gate import approval_gate_node


def test_approval_gate_auto_approve():
    state = {"asset_id": "asset-1", "vulnerability_id": "vuln-1", "cvss_score": 4.0,
        "remediation_plan": {"remediation_type": "config_only", "target_host": "10.0.0.1"},
        "asset_tier": "dev", "approval_status": "pending",
        "approval_policy": {"max_auto_approve_cvss": 7.0, "auto_approve_config_only": True, "require_approval_for_service_restart": True},
        "global_mode": "auto"}
    result = approval_gate_node(state)
    assert result["approval_status"] == "approved"
    assert result["approval_auto_approved"] is True


def test_approval_gate_requires_manual():
    state = {"asset_id": "asset-1", "vulnerability_id": "vuln-1", "cvss_score": 9.5,
        "remediation_plan": {"remediation_type": "kernel_patch", "target_host": "10.0.0.1"},
        "asset_tier": "prod", "approval_status": "pending",
        "approval_policy": {"max_auto_approve_cvss": 7.0, "auto_approve_config_only": True, "require_approval_for_service_restart": True},
        "global_mode": "auto"}
    result = approval_gate_node(state)
    assert result["approval_status"] == "waiting"
    assert result["approval_auto_approved"] is False


def test_approval_gate_manual_mode():
    state = {"asset_id": "asset-1", "vulnerability_id": "vuln-1", "cvss_score": 2.0,
        "remediation_plan": {"remediation_type": "config_only", "target_host": "10.0.0.1"},
        "asset_tier": "dev", "approval_status": "pending",
        "approval_policy": {"max_auto_approve_cvss": 10.0, "auto_approve_config_only": True, "require_approval_for_service_restart": False},
        "global_mode": "manual"}
    result = approval_gate_node(state)
    assert result["approval_status"] == "waiting"
