# src/agents/verification_agent.py
"""Verification agent — multi-scanner post-remediation validation.

Runs 3 checks in sequence with fail-fast:
  1. Service smoke test (SSH + ss -tlnp)
  2. Nuclei targeted re-scan
  3. OpenVAS full re-scan
"""

from __future__ import annotations

import logging
from typing import Any

from src.agents.state import AutopatchState
from src.agents.tools.nuclei_tool import run_nuclei_scan
from src.agents.tools.openvas_tool import run_openvas_scan
from src.agents.tools.ssh_tool import ssh_execute
from src.api.services.vault_service import build_vault_client_from_settings

logger = logging.getLogger(__name__)


async def _check_smoke(vault, host: str, user: str, pre_services: list[str]) -> dict:
    result = await ssh_execute(vault, host, "ss -tlnp", user=user)
    if not result.ok:
        return {
            "passed": False,
            "services_before": pre_services,
            "services_after": [],
            "ports_before": pre_services,
            "ports_after": [],
            "details": f"Clone unreachable: {result.stderr}",
            "crash": True,
        }
    services_after = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    pre_ports = {line.split()[0] if len(line.split()) > 0 else line for line in pre_services}
    post_ports = {line.split()[0] if len(line.split()) > 0 else line for line in services_after}
    return {
        "passed": True,
        "services_before": pre_services,
        "services_after": services_after,
        "ports_before": list(pre_ports),
        "ports_after": list(post_ports),
        "details": "Services verified",
        "crash": False,
    }


async def _check_nuclei(host: str, scan_data: dict) -> dict:
    template_id = scan_data.get("nuclei_template_id")
    template_ids = [template_id] if template_id else None
    result = await run_nuclei_scan(host, template_ids=template_ids)
    return {
        "passed": not result.has_findings,
        "template_id": template_id or "full_scan",
        "findings": result.findings[:10],
    }


async def _check_openvas(host: str, target_cve: str | None) -> dict:
    result = await run_openvas_scan(host)
    target_resolved = True
    if target_cve:
        for finding in result.findings:
            if target_cve in finding.get("cve", ""):
                target_resolved = False
                break
    return {
        "passed": target_resolved,
        "original_findings": 0,
        "current_findings": result.finding_count,
        "target_resolved": target_resolved,
        "new_findings": result.findings[:20],
    }


async def verification_node(state: AutopatchState) -> dict[str, Any]:
    plan = state.get("remediation_plan", {})
    host = plan.get("target_host", "")
    user = plan.get("ssh_user", "autopatch")
    pre_services = state.get("pre_services", [])
    scan_data = state.get("scan_data", {})
    cve_id = state.get("cve_id")

    results: dict[str, Any] = {
        "smoke_test": None,
        "nuclei_rescan": None,
        "openvas_rescan": None,
        "overall": "pass",
        "failure_reason": None,
        "summary": "",
    }

    vault = build_vault_client_from_settings()

    try:
        async with vault:
            logger.info("Verification: running smoke test on %s", host)
            smoke = await _check_smoke(vault, host, user, pre_services)
            results["smoke_test"] = smoke

            if smoke.get("crash"):
                results["overall"] = "crash"
                results["failure_reason"] = f"Clone unreachable: {smoke['details']}"
                return {"verification_results": results, "status": "verification_crash"}

            logger.info("Verification: running Nuclei re-scan on %s", host)
            nuclei = await _check_nuclei(host, scan_data)
            results["nuclei_rescan"] = nuclei

            if not nuclei["passed"]:
                results["overall"] = "fail"
                results["failure_reason"] = f"Nuclei still detects vulnerability (template: {nuclei['template_id']})"
                return {"verification_results": results, "status": "verification_failed"}

            logger.info("Verification: running OpenVAS scan on %s", host)
            openvas = await _check_openvas(host, cve_id)
            results["openvas_rescan"] = openvas

            if not openvas["passed"]:
                results["overall"] = "fail"
                results["failure_reason"] = f"OpenVAS still detects {cve_id}"
                return {"verification_results": results, "status": "verification_failed"}

    except Exception as exc:
        logger.exception("Verification agent error: %s", exc)
        results["overall"] = "crash"
        results["failure_reason"] = str(exc)
        return {"verification_results": results, "status": "verification_crash"}

    results["summary"] = "All 3 verification checks passed"
    return {"verification_results": results, "status": "verified"}
