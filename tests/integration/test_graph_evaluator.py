from src.agents.state import make_initial_state
from src.agents.graph import build_graph

def test_graph_out_of_scope():
    graph = build_graph()
    state = make_initial_state("v1", "a1", "CVE-2024-99999", {
        "severity": "low", "cvss_score": 2.0, "epss_score": 0.01,
        "is_kev": False, "asset_criticality": "low",
    })
    result = graph.invoke(state)
    assert result["scope_decision"] == "out_of_scope"
    assert result["ssvc_decision"] == "track"
    assert result["status"] == "complete"

def test_graph_in_scope_stub():
    graph = build_graph()
    state = make_initial_state("v1", "a1", "CVE-2023-44487", {
        "severity": "critical", "cvss_score": 9.8, "epss_score": 0.94,
        "is_kev": True, "asset_criticality": "critical",
    })
    result = graph.invoke(state)
    assert result["scope_decision"] == "in_scope"
    assert result["ssvc_decision"] == "act"
    assert result["status"] == "complete"
