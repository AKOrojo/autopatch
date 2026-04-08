import json
from unittest.mock import patch, MagicMock

import pytest

from src.agents.state import AutopatchState
from src.agents.lead_agent import lead_node, _build_context


def _make_state(**overrides) -> AutopatchState:
    base: AutopatchState = {
        "vulnerability_id": "v1",
        "asset_id": "a1",
        "cve_id": "CVE-2024-1234",
        "scan_data": {
            "title": "OpenSSH RCE",
            "severity": "critical",
            "affected_package": "openssh-server",
            "affected_version": "8.9p1",
            "fixed_version": "9.3p2",
            "os_family": "ubuntu",
            "environment": "production",
        },
        "epss_score": 0.95,
        "is_kev": True,
        "cvss_score": 9.8,
        "ssvc_decision": "act",
        "priority_score": 92.5,
        "scope_decision": "in_scope",
        "scope_reason": "KEV=true → act → in_scope",
        "asset_criticality": "critical",
        "cve_details": {
            "cve_id": "CVE-2024-1234",
            "summary": "Remote code execution in OpenSSH 8.9p1",
            "fix_available": True,
            "fixed_version": "9.3p2",
        },
        "vendor_advisories": ["https://ubuntu.com/security/CVE-2024-1234"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        "doc_chunks": [
            "Run: apt-get update",
            "Run: apt-get install openssh-server=1:9.3p2-1ubuntu1",
        ],
        "doc_sources": ["https://ubuntu.com/security/CVE-2024-1234"],
        "remediation_plan": None,
        "strategy": None,
        "status": "researching",
        "error": None,
    }
    base.update(overrides)
    return base


def test_build_context_includes_all_sections():
    state = _make_state()
    ctx = _build_context(state)
    assert "## Vulnerability" in ctx
    assert "CVE-2024-1234" in ctx
    assert "## Asset" in ctx
    assert "apt-get" in ctx
    assert "## Research Summary" in ctx
    assert "## Documentation Guidance" in ctx
    assert "apt-get update" in ctx
    assert "## Vendor Advisories" in ctx


def test_build_context_no_docs():
    state = _make_state(doc_chunks=[], vendor_advisories=[])
    ctx = _build_context(state)
    assert "## Documentation Guidance" not in ctx
    assert "## Vendor Advisories" not in ctx


@pytest.mark.asyncio
async def test_lead_node_produces_plan():
    llm_response = json.dumps({
        "strategy": "vendor_patch",
        "confidence": "high",
        "summary": "Upgrade openssh-server to 9.3p2.",
        "pre_checks": ["dpkg -l openssh-server"],
        "steps": [
            {"description": "Update repos", "command": "apt-get update", "expected_output": "Done", "rollback": None},
            {"description": "Install fix", "command": "apt-get install -y openssh-server=9.3p2", "expected_output": "Setting up", "rollback": "apt-get install -y openssh-server=8.9p1"},
        ],
        "post_verification": [
            {"description": "Check version", "command": "dpkg -l openssh-server", "expected_output": "9.3p2"},
        ],
        "rollback_plan": "apt-get install -y openssh-server=8.9p1",
        "estimated_downtime": "< 30s",
        "risks": ["SSH restart interrupts connections"],
    })

    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message.content = llm_response

    state = _make_state()

    with patch("src.agents.lead_agent._call_llm", return_value=mock_completion):
        result = await lead_node(state)

    assert result["strategy"] == "vendor_patch"
    assert result["remediation_plan"]["confidence"] == "high"
    assert len(result["remediation_plan"]["steps"]) == 2
    assert result["status"] == "complete"


@pytest.mark.asyncio
async def test_lead_node_llm_failure_sets_error():
    state = _make_state()

    with patch("src.agents.lead_agent._call_llm", side_effect=Exception("LLM down")):
        result = await lead_node(state)

    assert result["status"] == "error"
    assert "LLM" in result["error"]
    assert result["remediation_plan"] is None


@pytest.mark.asyncio
async def test_lead_node_invalid_json_sets_error():
    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message.content = "This is not JSON at all"

    state = _make_state()

    with patch("src.agents.lead_agent._call_llm", return_value=mock_completion):
        result = await lead_node(state)

    assert result["status"] == "error"
    assert result["remediation_plan"] is None
