from src.agents.state import AutopatchState


def test_state_schema_accepts_minimal_input():
    state: AutopatchState = {
        "vulnerability_id": "abc-123",
        "asset_id": "def-456",
        "cve_id": None,
        "scan_data": {"title": "Test vuln", "severity": "high"},
        "epss_score": None,
        "is_kev": False,
        "cvss_score": None,
        "ssvc_decision": None,
        "priority_score": None,
        "scope_decision": "pending",
        "scope_reason": "",
        "asset_criticality": "medium",
        "cve_details": None,
        "vendor_advisories": [],
        "references": [],
        "doc_chunks": [],
        "doc_sources": [],
        "remediation_plan": None,
        "strategy": None,
        "status": "pending",
        "error": None,
    }
    assert state["vulnerability_id"] == "abc-123"
    assert state["status"] == "pending"


def test_state_schema_accepts_full_input():
    state: AutopatchState = {
        "vulnerability_id": "abc-123",
        "asset_id": "def-456",
        "cve_id": "CVE-2024-1234",
        "scan_data": {
            "title": "OpenSSH vulnerability",
            "severity": "critical",
            "affected_package": "openssh-server",
            "affected_version": "8.9p1",
            "fixed_version": "9.3p2",
        },
        "epss_score": 0.95,
        "is_kev": True,
        "cvss_score": 9.8,
        "ssvc_decision": "act",
        "priority_score": 92.5,
        "scope_decision": "in_scope",
        "scope_reason": "KEV=true, EPSS>=0.7 → act → in_scope",
        "asset_criticality": "critical",
        "cve_details": {"description": "Remote code execution"},
        "vendor_advisories": ["https://ubuntu.com/security/CVE-2024-1234"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        "doc_chunks": ["Upgrade openssh-server to 9.3p2"],
        "doc_sources": ["https://ubuntu.com/security/CVE-2024-1234"],
        "remediation_plan": {
            "strategy": "vendor_patch",
            "steps": ["apt-get update", "apt-get install openssh-server=9.3p2"],
            "rollback": "apt-get install openssh-server=8.9p1",
            "verification": "ssh -V",
        },
        "strategy": "vendor_patch",
        "status": "complete",
        "error": None,
    }
    assert state["strategy"] == "vendor_patch"
    assert state["remediation_plan"]["steps"][0] == "apt-get update"
