import json
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

from src.agents.state import AutopatchState
from src.agents.docs_agent import docs_node


def _make_state(**overrides) -> AutopatchState:
    base: AutopatchState = {
        "vulnerability_id": "v1",
        "asset_id": "a1",
        "cve_id": "CVE-2024-1234",
        "scan_data": {"title": "Test", "severity": "high", "affected_package": "openssh-server"},
        "epss_score": 0.5,
        "is_kev": False,
        "cvss_score": 7.5,
        "ssvc_decision": "attend",
        "priority_score": 60.0,
        "scope_decision": "in_scope",
        "scope_reason": "test",
        "asset_criticality": "medium",
        "cve_details": {"summary": "A vulnerability in OpenSSH"},
        "vendor_advisories": ["https://ubuntu.com/security/CVE-2024-1234"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
            "https://ubuntu.com/security/CVE-2024-1234",
        ],
        "doc_chunks": [],
        "doc_sources": [],
        "remediation_plan": None,
        "strategy": None,
        "status": "researching",
        "error": None,
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_docs_node_fetches_and_extracts():
    llm_response = json.dumps({
        "remediation_steps": [
            "Run: apt-get update",
            "Run: apt-get install openssh-server=9.3p2",
        ],
        "fixed_version": "openssh-server=9.3p2",
        "workaround": None,
        "sources": ["https://ubuntu.com/security/CVE-2024-1234"],
    })

    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message.content = llm_response

    state = _make_state()

    with patch("src.agents.docs_agent.fetch_url", new_callable=AsyncMock, return_value="Upgrade to 9.3p2..."), \
         patch("src.agents.docs_agent._call_llm", return_value=mock_completion):
        result = await docs_node(state)

    assert len(result["doc_chunks"]) == 2
    assert "apt-get update" in result["doc_chunks"][0]
    assert len(result["doc_sources"]) >= 1
    assert result["status"] == "researching"


@pytest.mark.asyncio
async def test_docs_node_no_references():
    state = _make_state(references=[], vendor_advisories=[])
    result = await docs_node(state)
    assert result["doc_chunks"] == []
    assert result["doc_sources"] == []
    assert result["status"] == "researching"


@pytest.mark.asyncio
async def test_docs_node_llm_error_returns_raw_text():
    state = _make_state()

    with patch("src.agents.docs_agent.fetch_url", new_callable=AsyncMock, return_value="Raw advisory text about upgrading"), \
         patch("src.agents.docs_agent._call_llm", side_effect=Exception("LLM down")):
        result = await docs_node(state)

    assert len(result["doc_chunks"]) >= 1
    assert "Raw advisory text" in result["doc_chunks"][0]


@pytest.mark.asyncio
async def test_docs_node_fetch_failure_returns_empty():
    state = _make_state()

    with patch("src.agents.docs_agent.fetch_url", new_callable=AsyncMock, return_value=None):
        result = await docs_node(state)

    assert result["doc_chunks"] == []
    assert result["doc_sources"] == ["https://ubuntu.com/security/CVE-2024-1234", "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"]
