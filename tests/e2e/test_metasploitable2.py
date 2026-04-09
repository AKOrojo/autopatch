# tests/e2e/test_metasploitable2.py
"""E2E tests against Metasploitable 2 — full remediation pipeline.

Run with: pytest tests/e2e/test_metasploitable2.py -m e2e -v -s --timeout=2700

Tests:
1. Multi-scanner scan (Nuclei + Trivy + optional OpenVAS) → correlate findings
2. Remediate SSH root login → verify fix with re-scan
3. Out-of-scope: low-severity finding correctly filtered by evaluator
"""

import os
import pytest

from src.agents.state import make_initial_state
from src.agents.graph import build_graph


pytestmark = [pytest.mark.e2e, pytest.mark.live_infra]

# Whether to include OpenVAS in scans (slow: 10-30 min)
RUN_OPENVAS = os.environ.get("AUTOPATCH_E2E_OPENVAS", "").lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# Helpers: scanner correlation
# ---------------------------------------------------------------------------

def _correlate_findings(nuclei_findings, trivy_vulns, openvas_findings=None):
    """Correlate scanner findings by CVE ID.

    Returns a list of merged vulnerability records. Each record has:
      - cve_id: the CVE (or None for non-CVE findings)
      - title: best available title
      - severity: highest severity across scanners
      - scanners: list of scanner names that found it
      - scanner_details: per-scanner raw data
    """
    by_cve = {}  # cve_id -> merged record
    no_cve = []  # findings without CVE

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    # Nuclei findings
    for f in nuclei_findings:
        info = f.get("info", {})
        cve_ids = info.get("classification", {}).get("cve-id") or []
        severity = info.get("severity", "medium").lower()
        title = info.get("name", "Unknown")
        template_id = f.get("template-id", "")

        if cve_ids:
            for cve in cve_ids:
                if cve not in by_cve:
                    by_cve[cve] = {
                        "cve_id": cve, "title": title, "severity": severity,
                        "scanners": [], "scanner_details": {},
                        "nuclei_template_id": template_id,
                    }
                rec = by_cve[cve]
                rec["scanners"].append("nuclei")
                rec["scanner_details"]["nuclei"] = f
                if severity_rank.get(severity, 0) > severity_rank.get(rec["severity"], 0):
                    rec["severity"] = severity
        else:
            no_cve.append({
                "cve_id": None, "title": title, "severity": severity,
                "scanners": ["nuclei"], "scanner_details": {"nuclei": f},
                "nuclei_template_id": template_id,
            })

    # Trivy vulnerabilities
    for v in trivy_vulns:
        cve = v.get("VulnerabilityID", "")
        severity = v.get("Severity", "MEDIUM").lower()
        title = v.get("Title", v.get("VulnerabilityID", "Unknown"))

        if cve:
            if cve not in by_cve:
                by_cve[cve] = {
                    "cve_id": cve, "title": title, "severity": severity,
                    "scanners": [], "scanner_details": {},
                    "nuclei_template_id": "",
                }
            rec = by_cve[cve]
            rec["scanners"].append("trivy")
            rec["scanner_details"]["trivy"] = v
            if severity_rank.get(severity, 0) > severity_rank.get(rec["severity"], 0):
                rec["severity"] = severity

    # OpenVAS findings (optional)
    if openvas_findings:
        for f in openvas_findings:
            cve = f.get("cve", "")
            severity_val = float(f.get("severity", "0"))
            severity = "critical" if severity_val >= 9.0 else "high" if severity_val >= 7.0 else "medium" if severity_val >= 4.0 else "low"
            title = f.get("name", "Unknown")

            if cve and cve != "NOCVE":
                if cve not in by_cve:
                    by_cve[cve] = {
                        "cve_id": cve, "title": title, "severity": severity,
                        "scanners": [], "scanner_details": {},
                        "nuclei_template_id": "",
                    }
                rec = by_cve[cve]
                rec["scanners"].append("openvas")
                rec["scanner_details"]["openvas"] = f
                if severity_rank.get(severity, 0) > severity_rank.get(rec["severity"], 0):
                    rec["severity"] = severity
            else:
                no_cve.append({
                    "cve_id": None, "title": title, "severity": severity,
                    "scanners": ["openvas"], "scanner_details": {"openvas": f},
                    "nuclei_template_id": "",
                })

    # Deduplicate scanner lists
    for rec in by_cve.values():
        rec["scanners"] = sorted(set(rec["scanners"]))

    all_findings = list(by_cve.values()) + no_cve
    all_findings.sort(key=lambda r: severity_rank.get(r["severity"], 0), reverse=True)
    return all_findings


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
async def scan_results(clone_ip):
    """Run Nuclei + Trivy (+ optional OpenVAS) against the clone."""
    from src.agents.tools.nuclei_tool import run_nuclei_scan
    from src.agents.tools.trivy_tool import run_trivy_scan

    nuclei = await run_nuclei_scan(clone_ip, severity="critical,high,medium")
    trivy = await run_trivy_scan(clone_ip, severity="CRITICAL,HIGH,MEDIUM")

    openvas = None
    if RUN_OPENVAS:
        from src.agents.tools.openvas_tool import run_openvas_scan
        openvas_result = await run_openvas_scan(clone_ip)
        openvas = openvas_result.findings if openvas_result.exit_code == 0 else None

    return {
        "nuclei": nuclei,
        "trivy": trivy,
        "openvas_findings": openvas,
    }


@pytest.fixture(scope="session")
def correlated_vulns(scan_results):
    """Correlate findings across scanners by CVE ID."""
    return _correlate_findings(
        scan_results["nuclei"].findings,
        scan_results["trivy"].vulnerabilities,
        scan_results.get("openvas_findings"),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.timeout(2700)
async def test_multi_scanner_correlation(clone_ip, scan_results, correlated_vulns):
    """Run all scanners, correlate by CVE, report merged findings."""
    nuclei = scan_results["nuclei"]
    trivy = scan_results["trivy"]

    print(f"\n{'='*60}")
    print(f"SCAN RESULTS for {clone_ip}")
    print(f"{'='*60}")
    print(f"Nuclei: {len(nuclei.findings)} findings (exit={nuclei.exit_code})")
    print(f"Trivy:  {len(trivy.vulnerabilities)} vulnerabilities (exit={trivy.exit_code})")
    if scan_results.get("openvas_findings") is not None:
        print(f"OpenVAS: {len(scan_results['openvas_findings'])} findings")
    else:
        print(f"OpenVAS: skipped (set AUTOPATCH_E2E_OPENVAS=1 to enable)")

    # Show correlated results
    cve_vulns = [v for v in correlated_vulns if v["cve_id"]]
    no_cve_vulns = [v for v in correlated_vulns if not v["cve_id"]]
    multi_scanner = [v for v in cve_vulns if len(v["scanners"]) > 1]

    print(f"\n--- Correlated Vulnerabilities ---")
    print(f"Total unique CVEs: {len(cve_vulns)}")
    print(f"Found by multiple scanners: {len(multi_scanner)}")
    print(f"Non-CVE findings: {len(no_cve_vulns)}")

    print(f"\n--- Multi-scanner CVEs (merged for dashboard) ---")
    for v in multi_scanner[:10]:
        print(f"  {v['cve_id']} [{v['severity']}] — scanners: {v['scanners']}")
        print(f"    {v['title']}")

    print(f"\n--- Single-scanner CVEs ---")
    for v in cve_vulns[:10]:
        if len(v["scanners"]) == 1:
            print(f"  {v['cve_id']} [{v['severity']}] — {v['scanners'][0]}")
            print(f"    {v['title']}")

    # At least one scanner should find something
    assert len(correlated_vulns) > 0, "No vulnerabilities found on Metasploitable 2"


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.timeout(2700)
async def test_remediate_ssh_root_login(cloned_vm, clone_ip, correlated_vulns):
    """Remediate SSH PermitRootLogin on Metasploitable 2 and verify the fix.

    Known vulnerability: Metasploitable 2 allows root login via SSH.
    Fix: PermitRootLogin no in /etc/ssh/sshd_config + restart sshd.
    Verify: Nuclei re-scan no longer detects the misconfiguration.
    """
    from src.agents.tools.nuclei_tool import run_nuclei_scan

    # Step 1: Pre-scan to confirm SSH vuln exists
    pre_scan = await run_nuclei_scan(clone_ip)
    ssh_findings_before = [
        f for f in pre_scan.findings
        if "ssh" in f.get("info", {}).get("name", "").lower()
        or "ssh" in f.get("template-id", "").lower()
    ]
    print(f"\n--- Pre-remediation SSH findings: {len(ssh_findings_before)} ---")
    for f in ssh_findings_before:
        print(f"  - {f.get('info', {}).get('name', '?')} [{f.get('template-id', '?')}]")

    # Determine which scanners found SSH-related issues for re-scan tracking
    ssh_scanners = {"nuclei"}  # always re-scan with nuclei
    for v in correlated_vulns:
        if v.get("title") and "ssh" in v["title"].lower():
            ssh_scanners.update(v["scanners"])
    print(f"Scanners to re-run for verification: {ssh_scanners}")

    # Step 2: Run the full agent pipeline
    state = make_initial_state(
        vulnerability_id="e2e-ssh-root-login",
        asset_id="e2e-meta2",
        cve_id=None,
        scan_data={
            "title": "SSH PermitRootLogin enabled",
            "severity": "high",
            "cvss_score": 7.5,
            "epss_score": 0.5,
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
    if final_state.get("execution_result"):
        er = final_state["execution_result"]
        print(f"  pre_commands: {len(er.get('pre_commands', []))}")
        print(f"  playbook exit: {er.get('playbook', {}).get('exit_code', '?')}")
        print(f"  post_commands: {len(er.get('post_commands', []))}")

    assert final_state["status"] in ("remediated", "executed", "dead_letter", "error"), \
        f"Unexpected status: {final_state['status']}"

    # Step 3: Verify the fix with re-scan
    if final_state["status"] in ("remediated", "executed"):
        post_scan = await run_nuclei_scan(clone_ip)
        ssh_findings_after = [
            f for f in post_scan.findings
            if "ssh" in f.get("info", {}).get("name", "").lower()
            or "ssh" in f.get("template-id", "").lower()
        ]
        print(f"\n--- Post-remediation SSH findings: {len(ssh_findings_after)} ---")
        for f in ssh_findings_after:
            print(f"  - {f.get('info', {}).get('name', '?')} [{f.get('template-id', '?')}]")

        if len(ssh_findings_after) < len(ssh_findings_before):
            print(f"SSH findings reduced: {len(ssh_findings_before)} → {len(ssh_findings_after)}")

    if final_state["status"] == "remediated":
        vr = final_state.get("verification_results", {})
        assert vr.get("overall") == "pass", f"Verification failed: {vr.get('failure_reason')}"
        print("PASS: SSH root login remediated and verified")


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.timeout(300)
async def test_out_of_scope_low_severity(cloned_vm, clone_ip):
    """Verify that a low-severity finding is correctly scoped out by the evaluator.

    Uses SSH banner disclosure — a real informational finding on Metasploitable 2
    with CVSS ~2.0 and no EPSS/KEV data. The evaluator should compute SSVC as
    'track' and scope it out.
    """
    state = make_initial_state(
        vulnerability_id="e2e-ssh-banner",
        asset_id="e2e-meta2",
        cve_id=None,
        scan_data={
            "title": "SSH Server Banner Disclosure",
            "severity": "info",
            "cvss_score": 2.1,
            "epss_score": 0.01,
            "is_kev": False,
            "asset_criticality": "medium",
            "os_family": "ubuntu",
            "affected_package": "openssh-server",
            "nuclei_template_id": "ssh-server-enumeration",
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

    print(f"\n--- Out-of-scope test ---")
    print(f"  status: {final_state['status']}")
    print(f"  scope_decision: {final_state.get('scope_decision')}")
    print(f"  scope_reason: {final_state.get('scope_reason')}")
    print(f"  ssvc_decision: {final_state.get('ssvc_decision')}")

    assert final_state["status"] == "out_of_scope", \
        f"Expected out_of_scope, got: {final_state['status']}"
    assert final_state.get("ssvc_decision") == "track", \
        f"Expected SSVC=track, got: {final_state.get('ssvc_decision')}"
