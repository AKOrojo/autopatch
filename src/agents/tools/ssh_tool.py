"""SSH command execution tool with JIT Vault-signed certificates."""

from __future__ import annotations

import asyncio
import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path

from src.api.services.vault_service import VaultClient

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SSHResult:
    """Result of a remote SSH command."""

    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


async def generate_ephemeral_keypair() -> tuple[Path, Path, str]:
    """Generate a temporary ED25519 keypair. Returns (private_path, public_path, public_key_text)."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="autopatch-ssh-"))
    private_key = tmp_dir / "id_ed25519"
    public_key = tmp_dir / "id_ed25519.pub"

    proc = await asyncio.create_subprocess_exec(
        "ssh-keygen",
        "-t", "ed25519",
        "-f", str(private_key),
        "-N", "",  # no passphrase
        "-C", "autopatch-jit",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    return private_key, public_key, public_key.read_text()


async def ssh_execute(
    vault: VaultClient,
    host: str,
    command: str,
    *,
    user: str = "autopatch",
    port: int = 22,
    ttl: str = "5m",
    timeout: int = 120,
) -> SSHResult:
    """Execute a command on a remote host using a JIT Vault-signed SSH certificate.

    Flow:
    1. Generate an ephemeral ED25519 keypair
    2. Send the public key to Vault for signing (short TTL)
    3. SSH to the target using the signed certificate
    4. Clean up all key material
    """
    private_key, public_key, pub_text = await generate_ephemeral_keypair()
    cert_path: Path | None = None

    try:
        # Sign the public key via Vault SSH CA
        cert = await vault.sign_public_key(
            pub_text,
            valid_principals=user,
            ttl=ttl,
        )
        cert_path = cert.write_to_tempfile()

        logger.info(
            "Executing SSH command on %s@%s:%d (cert serial=%s)",
            user, host, port, cert.serial_number,
        )

        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"CertificateFile={cert_path}",
            "-i", str(private_key),
            "-p", str(port),
            "-l", user,
            host,
            command,
        ]

        proc = await asyncio.create_subprocess_exec(
            *ssh_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            return SSHResult(exit_code=-1, stdout="", stderr="Command timed out")

        result = SSHResult(
            exit_code=proc.returncode or 0,
            stdout=stdout_bytes.decode(errors="replace"),
            stderr=stderr_bytes.decode(errors="replace"),
        )
        logger.info("SSH command exit_code=%d on %s", result.exit_code, host)
        return result

    finally:
        # Clean up ephemeral key material
        for path in [private_key, public_key, cert_path]:
            if path and path.exists():
                path.unlink(missing_ok=True)
        if private_key.parent.exists():
            try:
                private_key.parent.rmdir()
            except OSError:
                pass
