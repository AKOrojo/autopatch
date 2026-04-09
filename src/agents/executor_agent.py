"""Executor agent — runs remediation commands and Ansible playbooks on target hosts.

Enforces a 3-layer command sandbox (allowlist + argument validation + LLM policy)
before any remote execution.  Uses Vault-signed JIT SSH certificates for
authentication.  Captures pre-remediation service state for smoke-test comparison.
"""

from __future__ import annotations

import logging
from typing import Any

from src.agents.state import AutopatchState
from src.agents.tools.ansible_tool import (
    PlaybookSpec,
    generate_inventory,
    generate_playbook,
    run_playbook,
)
from src.agents.sandbox.sandbox_facade import SandboxFacade
from src.agents.tools.ssh_tool import generate_ephemeral_keypair, ssh_execute
from src.api.services.vault_service import build_vault_client_from_settings

logger = logging.getLogger(__name__)

sandbox = SandboxFacade()


async def _capture_pre_services(vault, host: str, user: str) -> list[str]:
    """Capture running services before remediation for smoke test comparison."""
    result = await ssh_execute(vault, host, "ss -tlnp", user=user)
    if result.ok:
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return []


async def executor_node(state: AutopatchState) -> dict[str, Any]:
    """LangGraph node that executes the remediation plan on the target host.

    Steps:
    1. Extract the remediation plan (commands + playbook spec)
    2. Validate every command through the 3-layer sandbox facade
    3. Acquire a JIT SSH certificate from Vault
    4. Capture pre-remediation service state (pre_services)
    5. Execute pre-flight commands via SSH
    6. Generate and run the Ansible playbook
    7. Execute post-flight verification commands
    8. Return execution results (including pre_services) to the graph state
    """
    plan = state.get("remediation_plan")
    if not plan:
        return {
            "status": "error",
            "error": "No remediation plan available for execution",
            "execution_result": None,
        }

    host = plan.get("target_host", "")
    if not host:
        return {
            "status": "error",
            "error": "No target_host in remediation plan",
            "execution_result": None,
        }

    strategy = state.get("strategy", "vendor_patch")
    pre_commands: list[str] = plan.get("pre_commands", [])
    post_commands: list[str] = plan.get("post_commands", [])
    playbook_vars: dict = plan.get("playbook_vars", {})
    user = plan.get("ssh_user", "autopatch")

    sandbox_context = {
        "vulnerability_id": state.get("vulnerability_id", ""),
        "cve_id": state.get("cve_id", ""),
        "strategy": strategy,
        "os_family": state.get("scan_data", {}).get("os_family", "unknown"),
    }

    # --- 1. Sandbox validation -----------------------------------------------
    all_commands = pre_commands + post_commands
    for cmd in all_commands:
        result = await sandbox.evaluate(cmd, sandbox_context)
        if not result.allowed:
            logger.warning("Sandbox rejected command: %s — %s (source: %s)", cmd, result.reason, result.source)
            return {
                "status": "error",
                "error": f"Command sandbox rejected: {result.reason}",
                "execution_result": {"blocked_command": cmd, "reason": result.reason, "source": result.source},
            }

    # --- 2. Vault JIT certificate --------------------------------------------
    vault = build_vault_client_from_settings()
    results: dict[str, Any] = {
        "pre_commands": [],
        "playbook": None,
        "post_commands": [],
        "pre_services": [],
    }

    try:
        async with vault:
            results["pre_services"] = await _capture_pre_services(vault, host, user)

            # --- 3. Pre-flight commands --------------------------------------
            for cmd in pre_commands:
                logger.info("Executing pre-command: %s", cmd)
                ssh_result = await ssh_execute(vault, host, cmd, user=user)
                results["pre_commands"].append({
                    "command": cmd,
                    "exit_code": ssh_result.exit_code,
                    "stdout": ssh_result.stdout[:2000],
                    "stderr": ssh_result.stderr[:2000],
                })
                if not ssh_result.ok:
                    return {
                        "status": "error",
                        "error": f"Pre-command failed: {cmd}",
                        "execution_result": results,
                    }

            # --- 4. Ansible playbook -----------------------------------------
            spec = PlaybookSpec(
                name=f"autopatch-{state['vulnerability_id']}",
                hosts="target",
                strategy=strategy,
                variables={
                    "vulnerability_id": state["vulnerability_id"],
                    "cve_id": state.get("cve_id", ""),
                    **playbook_vars,
                },
            )

            playbook_content = generate_playbook(spec)

            # Generate ephemeral keypair + cert for Ansible
            private_key, public_key, pub_text = await generate_ephemeral_keypair()
            try:
                cert = await vault.sign_public_key(pub_text, valid_principals=user, ttl="10m")
                cert_path = cert.write_to_tempfile()

                inventory_content = generate_inventory(
                    host=host,
                    user=user,
                    cert_file=str(cert_path),
                    private_key=str(private_key),
                )

                pb_result = await run_playbook(
                    playbook_content,
                    inventory_content,
                    extra_vars=playbook_vars,
                )
                results["playbook"] = {
                    "exit_code": pb_result.exit_code,
                    "stdout": pb_result.stdout[:5000],
                    "stderr": pb_result.stderr[:2000],
                }
            finally:
                for p in [private_key, public_key, cert_path]:
                    if p and p.exists():
                        p.unlink(missing_ok=True)
                if private_key.parent.exists():
                    try:
                        private_key.parent.rmdir()
                    except OSError:
                        pass

            if not pb_result.ok:
                return {
                    "status": "error",
                    "error": "Ansible playbook execution failed",
                    "execution_result": results,
                }

            # --- 5. Post-flight verification ---------------------------------
            for cmd in post_commands:
                logger.info("Executing post-command: %s", cmd)
                ssh_result = await ssh_execute(vault, host, cmd, user=user)
                results["post_commands"].append({
                    "command": cmd,
                    "exit_code": ssh_result.exit_code,
                    "stdout": ssh_result.stdout[:2000],
                    "stderr": ssh_result.stderr[:2000],
                })

    except Exception as exc:
        logger.exception("Executor failed: %s", exc)
        return {
            "status": "error",
            "error": f"Execution error: {exc}",
            "execution_result": results,
        }

    return {
        "status": "executed",
        "execution_result": results,
        "pre_services": results["pre_services"],
    }
