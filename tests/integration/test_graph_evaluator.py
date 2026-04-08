from src.agents.state import make_initial_state
from src.agents.graph import build_graph
import pytest


@pytest.mark.asyncio
async def test_graph_out_of_scope():
    """Low-severity vulns stop at evaluator — no LLM calls."""
    graph = build_graph()
    state = make_initial_state("v1", "a1", "CVE-2024-99999", {
        "severity": "low", "cvss_score": 2.0, "epss_score": 0.01,
        "is_kev": False, "asset_criticality": "low",
    })
    result = await graph.ainvoke(state)
    assert result["scope_decision"] == "out_of_scope"
    assert result["ssvc_decision"] == "track"
    assert result["status"] == "out_of_scope"
