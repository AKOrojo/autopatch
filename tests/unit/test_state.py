from src.agents.state import AutopatchState, make_initial_state

def test_make_initial_state():
    state = make_initial_state(
        vulnerability_id="vuln-123", asset_id="asset-456",
        cve_id="CVE-2023-44487", scan_data={"scanner": "nuclei"},
    )
    assert state["vulnerability_id"] == "vuln-123"
    assert state["asset_id"] == "asset-456"
    assert state["cve_id"] == "CVE-2023-44487"
    assert state["scope_decision"] == "pending"
    assert state["status"] == "pending"
    assert state["error"] is None
    assert state["vendor_advisories"] == []
    assert state["doc_chunks"] == []

def test_state_has_all_expected_keys():
    state = make_initial_state("v1", "a1", None, {})
    expected_keys = {
        "vulnerability_id", "asset_id", "cve_id", "scan_data",
        "epss_score", "is_kev", "cvss_score", "ssvc_decision",
        "priority_score", "scope_decision", "scope_reason",
        "cve_details", "vendor_advisories", "references",
        "doc_chunks", "doc_sources", "status", "error",
    }
    assert set(state.keys()) == expected_keys
