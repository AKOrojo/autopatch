import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from src.agents.state import make_initial_state
from src.agents.graph import build_graph


@pytest.mark.asyncio
async def test_full_graph_in_scope_mocked():
    """Full pipeline: evaluator (in_scope) -> research -> docs -> complete.
    LLM and URL fetches are mocked."""

    mock_nvd = {
        "cve_id": "CVE-2023-44487",
        "description": "HTTP/2 Rapid Reset",
        "cvss_v3_score": 7.5,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L",
        "references": ["https://example.com/advisory"],
        "affected_configs": [],
    }

    # Mock the LLM response object for research_agent
    mock_research_completion = MagicMock()
    mock_research_completion.choices = [MagicMock()]
    mock_research_completion.choices[0].message.content = (
        '{"summary": "Critical vuln", "vendor_advisories": ["https://example.com/advisory"], '
        '"fix_available": true, "fixed_version": "1.2.3", "references": ["https://example.com/advisory"]}'
    )
    mock_research_completion.choices[0].message.tool_calls = None

    # Mock the LLM response object for docs_agent
    mock_docs_completion = MagicMock()
    mock_docs_completion.choices = [MagicMock()]
    mock_docs_completion.choices[0].message.content = (
        '{"remediation_steps": ["Update to version 1.2.3"], "sources": ["https://example.com/advisory"]}'
    )
    mock_docs_completion.choices[0].message.tool_calls = None

    state = make_initial_state("v1", "a1", "CVE-2023-44487", {
        "severity": "critical",
        "title": "HTTP/2 Rapid Reset",
        "cvss_score": 9.8,
        "epss_score": 0.94,
        "is_kev": True,
        "asset_criticality": "critical",
    })

    with patch("src.agents.research_agent._get_enrichment_data", return_value=mock_nvd), \
         patch("src.agents.research_agent._call_llm", return_value=mock_research_completion), \
         patch("src.agents.docs_agent.fetch_url", new_callable=AsyncMock, return_value="Advisory content"), \
         patch("src.agents.docs_agent._call_llm", return_value=mock_docs_completion):

        graph = build_graph()
        result = await graph.ainvoke(state)

        assert result["scope_decision"] == "in_scope"
        assert result["ssvc_decision"] == "act"
        assert result["status"] == "complete"
