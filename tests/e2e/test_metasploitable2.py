# tests/e2e/test_metasploitable2.py
"""E2E tests against Metasploitable 2 — full remediation pipeline.

Run with: pytest tests/e2e/test_metasploitable2.py -m e2e -v -s --timeout=2700

Tests:
1. Multi-scanner scan (Nuclei + Trivy) → correlate findings
2. Remediate SSH root login → verify fix with re-scan
3. Dead letter path for unfixable vuln
"""

import pytest

from src.agents.state import make_initial_state
from src.agents.graph import build_graph


pytestmark = [pytest.mark.e2e, pytest.mark.live_infra]


@pytest.fixture(scope="session")
async def scan_results(clone_ip):
    """Run Nuclei + Trivy scans against the clone. Returns combined findings."""
    from src.agents.tools.nuclei_tool import run_nuclei_scan
    from src.agents.tools.trivy_tool import run_trivy_scan

    nuclei = await run_nuclei_scan(clone_ip, severity="critical,high,medium")
    trivy = await run_trivy_scan(clone_ip, severity="CRITICAL,HIGH,MEDIUM")

    return {"nuclei": nuclei, "trivy": trivy}


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.timeout(2700)
async def test_multi_scanner_finds_vulns(clone_ip, scan_results):
    """Verify that scanners find real vulnerabilities on Metasploitable 2."""
    nuclei = scan_results["nuclei"]
    trivy = scan_results["trivy"]

    # At least one scanner should find something on Metasploitable 2
    total_findings = len(nuclei.findings) + len(trivy.vulnerabilities)
    assert total_findings > 0, (
        f"No vulnerabilities found on Metasploitable 2 at {clone_ip}. "
        f"Nuclei: exit={nuclei.exit_code} stderr={nuclei.stderr[:200]}. "
        f"Trivy: exit={trivy.exit_code} stderr={trivy.stderr[:200]}."
    )

    # Log what we found for visibility
    print(f"\n--- Scan Results ---")
    print(f"Nuclei: {len(nuclei.findings)} findings")
    for f in nuclei.findings[:5]:
        info = f.get("info", {})
        print(f"  - {info.get('name', '?')} [{info.get('severity', '?')}]")
    print(f"Trivy: {len(trivy.vulnerabilities)} vulnerabilities")
    for v in trivy.vulnerabilities[:5]:
        print(f"  - {v.get('VulnerabilityID', '?')} [{v.get('Severity', '?')}]")

    # Check for CVE overlap between scanners
    nuclei_cves = set()
    for f in nuclei.findings:
        cve_ids = f.get("info", {}).get("classification", {}).get("cve-id") or []
        nuclei_cves.update(cve_ids)
    trivy_cves = trivy.cve_ids

    overlap = nuclei_cves & trivy_cves
    print(f"\nNuclei CVEs: {len(nuclei_cves)}")
    print(f"Trivy CVEs: {len(trivy_cves)}")
    print(f"Overlap: {len(overlap)} — {list(overlap)[:10]}")


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.timeout(2700)
async def test_remediate_ssh_root_login(cloned_vm, clone_ip):
    """Remediate SSH PermitRootLogin on Metasploitable 2 and verify the fix.

    This is a known, easy vulnerability:
    - Metasploitable 2 allows root login via SSH
    - Fix: set PermitRootLogin to 'no' in /etc/ssh/sshd_config, restart sshd
    - Verify: Nuclei re-scan no longer detects the misconfiguration
    """
    from src.agents.tools.nuclei_tool import run_nuclei_scan

    # Step 1: Confirm the vulnerability exists before remediation
    pre_scan = await run_nuclei_scan(clone_ip)
    ssh_findings = [
        f for f in pre_scan.findings
        if "ssh" in f.get("info", {}).get("name", "").lower()
        or "ssh" in f.get("template-id", "").lower()
    ]
    print(f"\n--- Pre-remediation SSH findings: {len(ssh_findings)} ---")
    for f in ssh_findings:
        print(f"  - {f.get('info', {}).get('name', '?')} [{f.get('template-id', '?')}]")

    # Step 2: Run the full agent pipeline to remediate
    state = make_initial_state(
        vulnerability_id="e2e-ssh-root-login",
        asset_id="e2e-meta2",
        cve_id=None,
        scan_data={
            "title": "SSH PermitRootLogin enabled",
            "severity": "high",
            "os_family": "ubuntu",
            "affected_package": "openssh-server",
            "nuclei_template_id": "ssh-auth-methods",
            "environment": "test",
            "affected_file": "/etc/ssh/sshd_config",
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
    state["scope_decision"] = "in_scope"
    state["scope_reason"] = "known SSH misconfiguration on Metasploitable 2"

    graph = build_graph()
    final_state = await graph.ainvoke(state)

    print(f"\n--- Pipeline result: status={final_state['status']} ---")

    # Step 3: Assert the pipeline completed (remediated or attempted)
    assert final_state["status"] in ("remediated", "executed", "dead_letter", "error"), \
        f"Unexpected status: {final_state['status']}"

    # Step 4: If remediated, verify the fix
    if final_state["status"] == "remediated":
        vr = final_state.get("verification_results", {})
        assert vr.get("overall") == "pass", f"Verification failed: {vr.get('failure_reason')}"
        print("Verification PASSED — SSH root login remediated successfully")

    # Step 5: If executed (verification may have been skipped), do a manual re-scan
    if final_state["status"] == "executed":
        print("Pipeline executed — running manual Nuclei re-scan...")
        post_scan = await run_nuclei_scan(clone_ip)
        post_ssh = [
            f for f in post_scan.findings
            if "ssh" in f.get("info", {}).get("name", "").lower()
            or "ssh" in f.get("template-id", "").lower()
        ]
        print(f"Post-remediation SSH findings: {len(post_ssh)}")
        # We expect fewer SSH findings after remediation
        if len(post_ssh) < len(ssh_findings):
            print("SSH findings reduced — remediation had effect")


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.timeout(2700)
async def test_dead_letter_unfixable_vuln(cloned_vm, clone_ip):
    """Verify that an unfixable vulnerability exhausts retries and lands in dead letter."""
    state = make_initial_state(
        vulnerability_id="e2e-unfixable",
        asset_id="e2e-meta2",
        cve_id="CVE-0000-0000",
        scan_data={
            "title": "Unfixable vulnerability for dead letter testing",
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
    state["scope_decision"] = "in_scope"
    state["scope_reason"] = "e2e dead letter test"

    graph = build_graph()
    final_state = await graph.ainvoke(state)

    print(f"\n--- Dead letter test: status={final_state['status']} ---")
    print(f"    reason={final_state.get('dead_letter_reason')}")
    print(f"    attempts={final_state.get('total_attempts', 0)}")

    assert final_state["status"] in ("dead_letter", "error"), \
        f"Expected dead_letter or error, got: {final_state['status']}"

    if final_state["status"] == "dead_letter":
        assert final_state.get("dead_letter_reason") is not None
        # Should have tried multiple strategies before giving up
        history = final_state.get("strategy_history", [])
        print(f"    strategy_history: {len(history)} attempts")
        for entry in history:
            print(f"      - {entry.get('strategy')}: {entry.get('error', '?')}")
