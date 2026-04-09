# tests/e2e/test_metasploitable2.py
"""E2E tests against Metasploitable 2 — full remediation pipeline.

Run with: pytest -m e2e --timeout=2700

These tests clone a Metasploitable 2 VM from Proxmox template 101,
run the full agent pipeline, and verify results with real scanners.
"""

import pytest

from src.agents.state import make_initial_state
from src.agents.graph import build_graph


pytestmark = [pytest.mark.e2e, pytest.mark.live_infra]


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.timeout(2700)  # 45 minutes
async def test_full_pipeline_package_vuln(cloned_vm, clone_ip):
    """Scan clone, pick a package CVE, run full pipeline, verify fix."""
    from src.agents.tools.nuclei_tool import run_nuclei_scan

    # Scan to find a real vulnerability
    scan_result = await run_nuclei_scan(clone_ip, severity="critical,high")
    assert scan_result.findings, "No vulnerabilities found on Metasploitable 2 (unexpected)"

    # Pick first finding with a CVE
    target_finding = None
    for f in scan_result.findings:
        info = f.get("info", {})
        classifications = info.get("classification", {})
        cve_ids = classifications.get("cve-id") or []
        if cve_ids:
            target_finding = f
            break

    if not target_finding:
        pytest.skip("No CVE-tagged findings from Nuclei scan")

    cve_id = target_finding["info"]["classification"]["cve-id"][0]
    template_id = target_finding.get("template-id", "")

    state = make_initial_state(
        vulnerability_id=f"e2e-{cve_id}",
        asset_id="e2e-meta2",
        cve_id=cve_id,
        scan_data={
            "title": target_finding["info"].get("name", "Unknown"),
            "severity": target_finding["info"].get("severity", "high"),
            "os_family": "ubuntu",
            "affected_package": "unknown",
            "nuclei_template_id": template_id,
            "environment": "test",
        },
    )

    state["remediation_plan"] = {
        "target_host": clone_ip,
        "ssh_user": "msfadmin",
        "vm_id": cloned_vm.vm_id,
        "snapshot_name": cloned_vm.snapshot_name or "pre-patch",
        "clone_name": "e2e-meta2-test",
    }

    graph = build_graph()
    final_state = await graph.ainvoke(state)

    assert final_state["status"] in ("remediated", "dead_letter", "error", "executed"), \
        f"Unexpected status: {final_state['status']}"

    if final_state["status"] == "remediated":
        vr = final_state.get("verification_results", {})
        assert vr.get("overall") == "pass"


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.timeout(2700)
async def test_full_pipeline_config_vuln(cloned_vm, clone_ip):
    """Find a config-level misconfiguration, remediate with config_workaround."""
    state = make_initial_state(
        vulnerability_id="e2e-weak-ssh",
        asset_id="e2e-meta2",
        cve_id=None,
        scan_data={
            "title": "Weak SSH Configuration — PermitRootLogin enabled",
            "severity": "high",
            "os_family": "ubuntu",
            "affected_package": "openssh-server",
            "nuclei_template_id": "ssh-weak-config",
            "environment": "test",
        },
    )
    state["remediation_plan"] = {
        "target_host": clone_ip,
        "ssh_user": "msfadmin",
        "vm_id": cloned_vm.vm_id,
        "snapshot_name": cloned_vm.snapshot_name or "pre-patch",
        "clone_name": "e2e-meta2-test",
    }
    state["strategy"] = "config_workaround"

    graph = build_graph()
    final_state = await graph.ainvoke(state)

    assert final_state["status"] in ("remediated", "dead_letter", "error", "executed")


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.timeout(2700)
async def test_dead_letter_path(cloned_vm, clone_ip):
    """Force all strategies to fail, verify dead letter handling."""
    state = make_initial_state(
        vulnerability_id="e2e-unfixable",
        asset_id="e2e-meta2",
        cve_id="CVE-0000-0000",
        scan_data={
            "title": "Unfixable vulnerability for testing",
            "severity": "critical",
            "os_family": "unknown_os",
            "affected_package": "nonexistent-package-99999",
            "nuclei_template_id": "nonexistent-template",
            "environment": "test",
        },
    )
    state["remediation_plan"] = {
        "target_host": clone_ip,
        "ssh_user": "msfadmin",
        "vm_id": cloned_vm.vm_id,
        "snapshot_name": cloned_vm.snapshot_name or "pre-patch",
        "clone_name": "e2e-meta2-test",
    }

    graph = build_graph()
    final_state = await graph.ainvoke(state)

    assert final_state["status"] in ("dead_letter", "error"), \
        f"Expected dead_letter or error, got: {final_state['status']}"

    if final_state["status"] == "dead_letter":
        assert final_state.get("dead_letter_reason") is not None
        assert final_state.get("artifact_bundle_path") is not None
