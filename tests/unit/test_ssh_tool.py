"""Unit tests for the SSH tool."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.tools.ssh_tool import SSHResult, generate_ephemeral_keypair, ssh_execute


class TestSSHResult:
    def test_ok_on_zero_exit(self):
        r = SSHResult(exit_code=0, stdout="ok", stderr="")
        assert r.ok is True

    def test_not_ok_on_nonzero_exit(self):
        r = SSHResult(exit_code=1, stdout="", stderr="error")
        assert r.ok is False

    def test_not_ok_on_timeout(self):
        r = SSHResult(exit_code=-1, stdout="", stderr="timed out")
        assert r.ok is False


class TestGenerateEphemeralKeypair:
    @pytest.mark.asyncio
    async def test_calls_ssh_keygen_ed25519(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("src.agents.tools.ssh_tool.asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            with patch("src.agents.tools.ssh_tool.Path.read_text", return_value="ssh-ed25519 AAAA test"):
                private_key, public_key, pub_text = await generate_ephemeral_keypair()

            # Verify ssh-keygen was called with ED25519
            call_args = mock_exec.call_args[0]
            assert "ssh-keygen" in call_args
            assert "-t" in call_args
            assert "ed25519" in call_args

        assert pub_text == "ssh-ed25519 AAAA test"
        assert private_key.name == "id_ed25519"
        assert public_key.name == "id_ed25519.pub"


class TestSSHExecute:
    @pytest.mark.asyncio
    async def test_successful_execution(self):
        mock_vault = AsyncMock()
        mock_cert = MagicMock()
        mock_cert.signed_key = "ssh-rsa-cert SIGNED"
        mock_cert.serial_number = "1234"
        mock_cert.write_to_tempfile.return_value = Path("/tmp/fake-cert.pub")
        mock_vault.sign_public_key = AsyncMock(return_value=mock_cert)

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"hello\n", b""))
        mock_proc.returncode = 0

        with (
            patch("src.agents.tools.ssh_tool.generate_ephemeral_keypair", new_callable=AsyncMock,
                  return_value=(Path("/tmp/fk"), Path("/tmp/fk.pub"), "ssh-ed25519 AAAA")),
            patch("src.agents.tools.ssh_tool.asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("src.agents.tools.ssh_tool.Path.exists", return_value=False),
        ):
            result = await ssh_execute(mock_vault, "10.0.0.5", "whoami")

        assert result.ok
        assert result.stdout == "hello\n"
        assert result.exit_code == 0
        mock_vault.sign_public_key.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_timeout_returns_error(self):
        mock_vault = AsyncMock()
        mock_cert = MagicMock()
        mock_cert.signed_key = "cert"
        mock_cert.serial_number = "5678"
        mock_cert.write_to_tempfile.return_value = Path("/tmp/fake-cert.pub")
        mock_vault.sign_public_key = AsyncMock(return_value=mock_cert)

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_proc.kill = MagicMock()

        with (
            patch("src.agents.tools.ssh_tool.generate_ephemeral_keypair", new_callable=AsyncMock,
                  return_value=(Path("/tmp/fk"), Path("/tmp/fk.pub"), "ssh-ed25519 AAAA")),
            patch("src.agents.tools.ssh_tool.asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("src.agents.tools.ssh_tool.asyncio.wait_for", side_effect=asyncio.TimeoutError()),
            patch("src.agents.tools.ssh_tool.Path.exists", return_value=False),
        ):
            result = await ssh_execute(mock_vault, "10.0.0.5", "sleep 999", timeout=1)

        assert result.exit_code == -1
        assert "timed out" in result.stderr.lower()

    @pytest.mark.asyncio
    async def test_cleanup_runs_on_success(self):
        mock_vault = AsyncMock()
        mock_cert = MagicMock()
        mock_cert.signed_key = "cert"
        mock_cert.serial_number = "9999"
        mock_cert.write_to_tempfile.return_value = Path("/tmp/test-cert.pub")
        mock_vault.sign_public_key = AsyncMock(return_value=mock_cert)

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"ok", b""))
        mock_proc.returncode = 0

        unlinked = []

        with (
            patch("src.agents.tools.ssh_tool.generate_ephemeral_keypair", new_callable=AsyncMock,
                  return_value=(Path("/tmp/fk"), Path("/tmp/fk.pub"), "ssh-ed25519 AAAA")),
            patch("src.agents.tools.ssh_tool.asyncio.create_subprocess_exec", return_value=mock_proc),
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "unlink", side_effect=lambda **kw: unlinked.append(True)),
            patch.object(Path, "rmdir"),
        ):
            result = await ssh_execute(mock_vault, "10.0.0.5", "whoami")

        assert result.ok
        # 3 files should be cleaned up: private key, public key, cert
        assert len(unlinked) == 3
