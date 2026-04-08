import json
import os
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("API_KEYS", "key1")

from src.agents.state import make_initial_state
from src.agents.graph import build_graph


@pytest.mark.asyncio
async def test_graph_out_of_scope_skips_agents():
    """Low-severity vulns should be evaluated and stopped — no LLM calls."""
    graph = build_graph()
    state = make_initial_state(
        "v1", "a1", None,
        {"title": "Info disclosure", "severity": "low", "cvss_score": 2.0,
         "epss_score": 0.01, "is_kev": False, "asset_criticality": "low"},
    )
    result = await graph.ainvoke(state)
    assert result["scope_decision"] == "out_of_scope"
    assert result["ssvc_decision"] == "track"
    assert result["status"] == "out_of_scope"
    assert result["remediation_plan"] is None


@pytest.mark.asyncio
async def test_graph_in_scope_full_pipeline():
    """Critical KEV vuln should go through research → docs → lead."""
    research_response = json.dumps({
        "summary": "OpenSSH 8.9p1 RCE",
        "vendor_advisories": ["https://ubuntu.com/security/CVE-2024-1234"],
        "fix_available": True,
        "fixed_version": "9.3p2",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
    })

    docs_response = json.dumps({
        "remediation_steps": ["apt-get update", "apt-get install openssh-server=9.3p2"],
        "fixed_version": "openssh-server=9.3p2",
        "workaround": None,
        "sources": ["https://ubuntu.com/security/CVE-2024-1234"],
    })

    lead_response = json.dumps({
        "strategy": "vendor_patch",
        "confidence": "high",
        "summary": "Upgrade openssh-server to 9.3p2",
        "pre_checks": ["dpkg -l openssh-server"],
        "steps": [
            {"description": "Update repos", "command": "apt-get update", "expected_output": "Done", "rollback": None},
        ],
        "post_verification": [
            {"description": "Check ver", "command": "dpkg -l openssh-server", "expected_output": "9.3p2"},
        ],
        "rollback_plan": "apt-get install openssh-server=8.9p1",
        "estimated_downtime": "< 30s",
        "risks": [],
    })

    call_count = {"n": 0}
    responses = [research_response, docs_response, lead_response]

    def mock_llm_call(messages, **kwargs):
        mock = MagicMock()
        mock.choices = [MagicMock()]
        idx = min(call_count["n"], len(responses) - 1)
        mock.choices[0].message.content = responses[idx]
        call_count["n"] += 1
        return mock

    enrichment_data = {
        "cve_id": "CVE-2024-1234",
        "description": "OpenSSH RCE",
        "cvss_v3_score": 9.8,
        "cvss_v3_vector": None,
        "references": [{"url": "https://ubuntu.com/security/CVE-2024-1234"}],
        "affected_configs": [],
    }

    graph = build_graph()
    state = make_initial_state(
        "v1", "a1", "CVE-2024-1234",
        {"title": "OpenSSH RCE", "severity": "critical", "cvss_score": 9.8,
         "epss_score": 0.94, "is_kev": True, "asset_criticality": "critical",
         "affected_package": "openssh-server", "affected_version": "8.9p1"},
    )

    with patch("src.agents.research_agent._get_enrichment_data", return_value=enrichment_data), \
         patch("src.agents.research_agent._call_llm", side_effect=mock_llm_call), \
         patch("src.agents.docs_agent.fetch_url", new_callable=AsyncMock, return_value="Upgrade to 9.3p2"), \
         patch("src.agents.docs_agent._call_llm", side_effect=mock_llm_call), \
         patch("src.agents.lead_agent._call_llm", side_effect=mock_llm_call):
        result = await graph.ainvoke(state)

    assert result["scope_decision"] == "in_scope"
    assert result["ssvc_decision"] == "act"
    assert result["status"] == "complete"
    assert result["strategy"] == "vendor_patch"
    assert result["remediation_plan"] is not None
    assert result["remediation_plan"]["confidence"] == "high"


@pytest.mark.asyncio
async def test_graph_no_cve_still_completes():
    """Vulns without CVE IDs should still go through the pipeline."""
    lead_response = json.dumps({
        "strategy": "config_workaround",
        "confidence": "medium",
        "summary": "Apply config fix",
        "pre_checks": [],
        "steps": [{"description": "Fix config", "command": "echo fix", "expected_output": "fix", "rollback": None}],
        "post_verification": [],
        "rollback_plan": "revert config",
        "estimated_downtime": "none",
        "risks": [],
    })

    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message.content = lead_response

    graph = build_graph()
    state = make_initial_state(
        "v1", "a1", None,
        {"title": "Weak TLS config", "severity": "high", "cvss_score": 7.5,
         "epss_score": 0.1, "is_kev": False, "asset_criticality": "medium"},
    )

    with patch("src.agents.lead_agent._call_llm", return_value=mock_completion):
        result = await graph.ainvoke(state)

    assert result["scope_decision"] == "in_scope"
    assert result["status"] == "complete"
    assert result["strategy"] == "config_workaround"
