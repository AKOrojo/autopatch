# tests/unit/test_verification_agent.py
"""Unit tests for the verification agent."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.agents.verification_agent import verification_node


def _make_state(**overrides):
    base = {
        "vulnerability_id": "vuln-1",
        "asset_id": "asset-1",
        "cve_id": "CVE-2024-1234",
        "scan_data": {"os_family": "ubuntu", "severity": "high", "nuclei_template_id": "CVE-2024-1234"},
        "remediation_plan": {"target_host": "10.0.0.5", "ssh_user": "autopatch"},
        "strategy": "vendor_patch",
        "pre_services": ["LISTEN 0.0.0.0:22", "LISTEN 0.0.0.0:80"],
        "execution_result": {"playbook": {"exit_code": 0}},
        "status": "executed",
    }
    base.update(overrides)
    return base


class TestVerificationSmoke:
    @pytest.mark.asyncio
    async def test_smoke_pass_when_services_match(self):
        with patch("src.agents.verification_agent.ssh_execute") as mock_ssh, \
             patch("src.agents.verification_agent.run_nuclei_scan") as mock_nuclei, \
             patch("src.agents.verification_agent.run_openvas_scan") as mock_openvas:

            mock_ssh.return_value = MagicMock(ok=True, stdout="LISTEN 0.0.0.0:22\nLISTEN 0.0.0.0:80\n", exit_code=0)
            mock_nuclei.return_value = MagicMock(findings=[], exit_code=0, has_findings=False)
            mock_openvas.return_value = MagicMock(findings=[], exit_code=0, finding_count=0)

            with patch("src.agents.verification_agent.build_vault_client_from_settings") as mock_vault:
                vault_ctx = AsyncMock()
                mock_vault.return_value = vault_ctx
                vault_ctx.__aenter__ = AsyncMock(return_value=vault_ctx)
                vault_ctx.__aexit__ = AsyncMock(return_value=False)

                result = await verification_node(_make_state())
                assert result["verification_results"]["overall"] == "pass"


class TestVerificationCrash:
    @pytest.mark.asyncio
    async def test_crash_when_clone_unreachable(self):
        with patch("src.agents.verification_agent.ssh_execute") as mock_ssh:
            mock_ssh.return_value = MagicMock(ok=False, stdout="", stderr="Connection refused", exit_code=255)

            with patch("src.agents.verification_agent.build_vault_client_from_settings") as mock_vault:
                vault_ctx = AsyncMock()
                mock_vault.return_value = vault_ctx
                vault_ctx.__aenter__ = AsyncMock(return_value=vault_ctx)
                vault_ctx.__aexit__ = AsyncMock(return_value=False)

                result = await verification_node(_make_state())
                assert result["verification_results"]["overall"] == "crash"


class TestVerificationFail:
    @pytest.mark.asyncio
    async def test_fail_when_nuclei_still_finds_vuln(self):
        with patch("src.agents.verification_agent.ssh_execute") as mock_ssh, \
             patch("src.agents.verification_agent.run_nuclei_scan") as mock_nuclei:

            mock_ssh.return_value = MagicMock(ok=True, stdout="LISTEN 0.0.0.0:22\nLISTEN 0.0.0.0:80\n", exit_code=0)
            mock_nuclei.return_value = MagicMock(
                findings=[{"template-id": "CVE-2024-1234", "matched-at": "http://10.0.0.5"}],
                exit_code=0,
                has_findings=True,
            )

            with patch("src.agents.verification_agent.build_vault_client_from_settings") as mock_vault:
                vault_ctx = AsyncMock()
                mock_vault.return_value = vault_ctx
                vault_ctx.__aenter__ = AsyncMock(return_value=vault_ctx)
                vault_ctx.__aexit__ = AsyncMock(return_value=False)

                result = await verification_node(_make_state())
                assert result["verification_results"]["overall"] == "fail"
                assert result["verification_results"]["nuclei_rescan"]["passed"] is False
