import os
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("API_KEYS", "key1")

from src.agents.evaluator_agent import compute_ssvc_decision, compute_priority_score, evaluator_node
from src.agents.state import make_initial_state

# SSVC decision tree
def test_ssvc_kev_true():
    assert compute_ssvc_decision(cvss=5.0, epss=0.1, is_kev=True, criticality="medium") == "act"

def test_ssvc_high_epss():
    assert compute_ssvc_decision(cvss=5.0, epss=0.8, is_kev=False, criticality="medium") == "act"

def test_ssvc_critical_cvss_critical_asset():
    assert compute_ssvc_decision(cvss=9.5, epss=0.1, is_kev=False, criticality="critical") == "act"

def test_ssvc_high_cvss():
    assert compute_ssvc_decision(cvss=7.5, epss=0.1, is_kev=False, criticality="medium") == "attend"

def test_ssvc_medium_epss():
    assert compute_ssvc_decision(cvss=3.0, epss=0.4, is_kev=False, criticality="medium") == "attend"

def test_ssvc_medium_cvss():
    assert compute_ssvc_decision(cvss=5.0, epss=0.1, is_kev=False, criticality="medium") == "track*"

def test_ssvc_low():
    assert compute_ssvc_decision(cvss=2.0, epss=0.01, is_kev=False, criticality="low") == "track"

def test_ssvc_none_values():
    assert compute_ssvc_decision(cvss=None, epss=None, is_kev=False, criticality="medium") == "track"

# Priority score
def test_priority_score_max():
    score = compute_priority_score(cvss=10.0, epss=1.0, is_kev=True, criticality="critical")
    assert score == 100.0

def test_priority_score_zero():
    score = compute_priority_score(cvss=0.0, epss=0.0, is_kev=False, criticality="low")
    assert score == 2.5

def test_priority_score_mid():
    score = compute_priority_score(cvss=7.0, epss=0.5, is_kev=False, criticality="medium")
    assert score == 50.5

# Evaluator node
def test_evaluator_node_in_scope():
    state = make_initial_state("v1", "a1", "CVE-2023-44487", {"severity": "high"})
    state["scan_data"]["cvss_score"] = 9.0
    state["scan_data"]["epss_score"] = 0.9
    state["scan_data"]["is_kev"] = True
    state["scan_data"]["asset_criticality"] = "critical"
    result = evaluator_node(state)
    assert result["scope_decision"] == "in_scope"
    assert result["ssvc_decision"] == "act"
    assert result["status"] == "evaluating"

def test_evaluator_node_out_of_scope():
    state = make_initial_state("v1", "a1", "CVE-2024-99999", {"severity": "low"})
    state["scan_data"]["cvss_score"] = 2.0
    state["scan_data"]["epss_score"] = 0.01
    state["scan_data"]["is_kev"] = False
    state["scan_data"]["asset_criticality"] = "low"
    result = evaluator_node(state)
    assert result["scope_decision"] == "out_of_scope"
    assert result["ssvc_decision"] == "track"
