"""Unit tests for the Ansible tool."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.tools.ansible_tool import (
    PlaybookSpec,
    generate_inventory,
    generate_playbook,
    run_playbook,
)


class TestPlaybookSpec:
    def test_vendor_patch_role_mapping(self):
        spec = PlaybookSpec(name="test", hosts="target", strategy="vendor_patch")
        assert spec.role_name == "patch-package"

    def test_config_workaround_role_mapping(self):
        spec = PlaybookSpec(name="test", hosts="target", strategy="config_workaround")
        assert spec.role_name == "config-fix"

    def test_compensating_control_role_mapping(self):
        spec = PlaybookSpec(name="test", hosts="target", strategy="compensating_control")
        assert spec.role_name == "compensating-control"

    def test_unknown_strategy_defaults_to_patch(self):
        spec = PlaybookSpec(name="test", hosts="target", strategy="unknown")
        assert spec.role_name == "patch-package"


class TestGeneratePlaybook:
    def test_generates_valid_json(self):
        spec = PlaybookSpec(
            name="patch-vuln-001",
            hosts="target",
            strategy="vendor_patch",
            variables={"package_name": "nginx"},
        )
        content = generate_playbook(spec)
        parsed = json.loads(content)
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_playbook_structure(self):
        spec = PlaybookSpec(
            name="patch-vuln-001",
            hosts="target",
            strategy="vendor_patch",
            variables={"package_name": "nginx"},
        )
        content = generate_playbook(spec)
        pb = json.loads(content)[0]
        assert pb["name"] == "patch-vuln-001"
        assert pb["hosts"] == "target"
        assert pb["become"] is True
        assert pb["vars"]["package_name"] == "nginx"
        assert pb["roles"][0]["role"] == "patch-package"
        assert len(pb["pre_tasks"]) == 1

    def test_playbook_includes_pre_check_role(self):
        spec = PlaybookSpec(name="test", hosts="target", strategy="vendor_patch")
        pb = json.loads(generate_playbook(spec))[0]
        pre_task = pb["pre_tasks"][0]
        assert pre_task["ansible.builtin.include_role"]["name"] == "pre-check"


class TestGenerateInventory:
    def test_basic_inventory(self):
        inv = generate_inventory("10.0.0.5", "autopatch")
        assert "[target]" in inv
        assert "10.0.0.5" in inv
        assert "ansible_user=autopatch" in inv

    def test_inventory_with_cert(self):
        inv = generate_inventory(
            "10.0.0.5", "autopatch",
            cert_file="/tmp/cert.pub",
            private_key="/tmp/id_ed25519",
        )
        assert "CertificateFile=/tmp/cert.pub" in inv
        assert "ansible_ssh_private_key_file=/tmp/id_ed25519" in inv

    def test_custom_port(self):
        inv = generate_inventory("10.0.0.5", "autopatch", port=2222)
        assert "ansible_port=2222" in inv


class TestRunPlaybook:
    @pytest.mark.asyncio
    async def test_successful_execution(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"PLAY RECAP ok=3", b""))
        mock_proc.returncode = 0

        with patch("src.agents.tools.ansible_tool.asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await run_playbook('[]', '[target]\nlocalhost\n')

        assert result.ok
        assert result.exit_code == 0
        assert "PLAY RECAP" in result.stdout

    @pytest.mark.asyncio
    async def test_check_mode_passes_flag(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"CHECK MODE", b""))
        mock_proc.returncode = 0

        with patch("src.agents.tools.ansible_tool.asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            await run_playbook('[]', '[target]\nlocalhost\n', check_mode=True)

        call_args = mock_exec.call_args[0]
        assert "--check" in call_args

    @pytest.mark.asyncio
    async def test_extra_vars_passed_as_json(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"ok", b""))
        mock_proc.returncode = 0

        with patch("src.agents.tools.ansible_tool.asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            await run_playbook('[]', '[target]\nlocalhost\n', extra_vars={"pkg": "nginx"})

        call_args = mock_exec.call_args[0]
        assert "--extra-vars" in call_args
        ev_idx = list(call_args).index("--extra-vars")
        assert '"pkg"' in call_args[ev_idx + 1]

    @pytest.mark.asyncio
    async def test_timeout_kills_process(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_proc.kill = MagicMock()

        with (
            patch("src.agents.tools.ansible_tool.asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("src.agents.tools.ansible_tool.asyncio.wait_for", side_effect=asyncio.TimeoutError()),
        ):
            result = await run_playbook('[]', '[target]\nlocalhost\n', timeout=1)

        assert result.exit_code == -1
        assert "timed out" in result.stderr.lower()

    @pytest.mark.asyncio
    async def test_temp_files_cleaned_up(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"ok", b""))
        mock_proc.returncode = 0

        with patch("src.agents.tools.ansible_tool.asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await run_playbook('[]', '[target]\nlocalhost\n')

        assert result.ok


class TestInventoryFormatting:
    def test_all_host_vars_on_single_line(self):
        """All host variables must be on the same line as the host for Ansible INI."""
        inv = generate_inventory(
            "10.0.0.5", "autopatch",
            cert_file="/tmp/cert.pub",
            private_key="/tmp/id_ed25519",
        )
        lines = [line for line in inv.strip().splitlines() if line.strip()]
        # Should have exactly 2 lines: [target] header and host line
        assert len(lines) == 2
        assert lines[0] == "[target]"
        assert "10.0.0.5" in lines[1]
        assert "ansible_user=autopatch" in lines[1]
        assert "CertificateFile=/tmp/cert.pub" in lines[1]
        assert "ansible_ssh_private_key_file=/tmp/id_ed25519" in lines[1]
