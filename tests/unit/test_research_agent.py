import json
from unittest.mock import patch, MagicMock

import pytest

from src.agents.state import AutopatchState
from src.agents.research_agent import research_node


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
        },
        "epss_score": 0.95,
        "is_kev": True,
        "cvss_score": 9.8,
        "ssvc_decision": "act",
        "priority_score": 92.5,
        "scope_decision": "in_scope",
        "scope_reason": "KEV=true → act → in_scope",
        "asset_criticality": "critical",
        "cve_details": None,
        "vendor_advisories": [],
        "references": [],
        "doc_chunks": [],
        "doc_sources": [],
        "remediation_plan": None,
        "strategy": None,
        "status": "evaluating",
        "error": None,
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_research_node_with_cve():
    llm_response = json.dumps({
        "summary": "OpenSSH 8.9p1 has a remote code execution vulnerability.",
        "vendor_advisories": ["https://ubuntu.com/security/CVE-2024-1234"],
        "fix_available": True,
        "fixed_version": "9.3p2",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
    })

    enrichment_data = {
        "cve_id": "CVE-2024-1234",
        "description": "OpenSSH RCE",
        "cvss_v3_score": 9.8,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "references": [{"url": "https://ubuntu.com/security/CVE-2024-1234"}],
        "affected_configs": [],
    }

    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message.content = llm_response

    state = _make_state()

    with patch("src.agents.research_agent._get_enrichment_data", return_value=enrichment_data), \
         patch("src.agents.research_agent._call_llm", return_value=mock_completion):
        result = await research_node(state)

    assert result["cve_details"]["summary"] == "OpenSSH 8.9p1 has a remote code execution vulnerability."
    assert "https://ubuntu.com/security/CVE-2024-1234" in result["vendor_advisories"]
    assert len(result["references"]) >= 1
    assert result["status"] == "researching"


@pytest.mark.asyncio
async def test_research_node_no_cve():
    state = _make_state(cve_id=None)
    result = await research_node(state)
    assert result["cve_details"] is None
    assert result["references"] == []
    assert result["status"] == "researching"


@pytest.mark.asyncio
async def test_research_node_llm_error_uses_nvd_fallback():
    enrichment_data = {
        "cve_id": "CVE-2024-1234",
        "description": "Test vuln description",
        "cvss_v3_score": 7.5,
        "cvss_v3_vector": None,
        "references": [{"url": "https://example.com/advisory"}],
        "affected_configs": [],
    }

    state = _make_state()

    with patch("src.agents.research_agent._get_enrichment_data", return_value=enrichment_data), \
         patch("src.agents.research_agent._call_llm", side_effect=Exception("LLM timeout")):
        result = await research_node(state)

    assert result["cve_details"] is not None
    assert result["cve_details"]["cve_id"] == "CVE-2024-1234"
    assert result["cve_details"]["description"] == "Test vuln description"
    assert result["status"] == "researching"
