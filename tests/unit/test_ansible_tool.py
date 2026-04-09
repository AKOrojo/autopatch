"""Unit tests for the Ansible tool."""

import json
from unittest.mock import MagicMock, patch

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


class TestRunPlaybookWithRunner:
    """Tests for the ansible-runner path."""

    def _mock_runner(self, rc=0, stdout="PLAY RECAP ok=3", stderr="", status="successful"):
        mock = MagicMock()
        mock.rc = rc
        mock.status = status
        mock.stdout.read.return_value = stdout
        mock.stderr.read.return_value = stderr
        return mock

    def _patch_runner(self, return_value=None, side_effect=None):
        """Inject a fake ansible_runner module and patch it for testing."""
        import src.agents.tools.ansible_tool as mod

        fake_module = MagicMock()
        if side_effect:
            fake_module.run = MagicMock(side_effect=side_effect)
        else:
            fake_module.run = MagicMock(return_value=return_value)

        return (
            patch.object(mod, "HAS_ANSIBLE_RUNNER", True),
            patch.object(mod, "ansible_runner", fake_module, create=True),
        )

    @pytest.mark.asyncio
    async def test_successful_execution(self):
        mock_result = self._mock_runner(rc=0, stdout="PLAY RECAP ok=3")
        p1, p2 = self._patch_runner(return_value=mock_result)

        with p1, p2:
            result = await run_playbook('[]', '[target]\nlocalhost\n')

        assert result.ok
        assert result.exit_code == 0
        assert "PLAY RECAP" in result.stdout

    @pytest.mark.asyncio
    async def test_check_mode_passes_flag(self):
        mock_result = self._mock_runner()
        p1, p2 = self._patch_runner(return_value=mock_result)

        with p1, p2 as fake_mod:
            await run_playbook('[]', '[target]\nlocalhost\n', check_mode=True)
            call_kwargs = fake_mod.run.call_args[1]

        assert "--check" in (call_kwargs.get("cmdline") or "")

    @pytest.mark.asyncio
    async def test_extra_vars_passed(self):
        mock_result = self._mock_runner()
        p1, p2 = self._patch_runner(return_value=mock_result)

        with p1, p2 as fake_mod:
            await run_playbook('[]', '[target]\nlocalhost\n', extra_vars={"pkg": "nginx"})
            call_kwargs = fake_mod.run.call_args[1]

        assert call_kwargs["extravars"] == {"pkg": "nginx"}

    @pytest.mark.asyncio
    async def test_failed_execution(self):
        mock_result = self._mock_runner(rc=2, stdout="", stderr="FATAL", status="failed")
        p1, p2 = self._patch_runner(return_value=mock_result)

        with p1, p2:
            result = await run_playbook('[]', '[target]\nlocalhost\n')

        assert not result.ok
        assert result.exit_code == 2

    @pytest.mark.asyncio
    async def test_exception_returns_error(self):
        p1, p2 = self._patch_runner(side_effect=RuntimeError("runner crashed"))

        with p1, p2:
            result = await run_playbook('[]', '[target]\nlocalhost\n')

        assert result.exit_code == -1
        assert "runner crashed" in result.stderr

    @pytest.mark.asyncio
    async def test_roles_path_set_in_envvars(self):
        mock_result = self._mock_runner()
        p1, p2 = self._patch_runner(return_value=mock_result)

        with p1, p2 as fake_mod:
            await run_playbook('[]', '[target]\nlocalhost\n')
            call_kwargs = fake_mod.run.call_args[1]

        assert "ANSIBLE_ROLES_PATH" in call_kwargs["envvars"]


class TestRunPlaybookSubprocessFallback:
    """Tests for the subprocess fallback path (Windows)."""

    @pytest.mark.asyncio
    async def test_falls_back_to_subprocess(self):
        from unittest.mock import AsyncMock
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"ok", b""))
        mock_proc.returncode = 0

        with (
            patch("src.agents.tools.ansible_tool.HAS_ANSIBLE_RUNNER", False),
            patch("src.agents.tools.ansible_tool.asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
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
