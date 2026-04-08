"""Ansible playbook generation and execution tool."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

logger = logging.getLogger(__name__)

ANSIBLE_ROLES_DIR = Path(__file__).resolve().parents[3] / "ansible" / "roles"
ANSIBLE_PLAYBOOKS_DIR = Path(__file__).resolve().parents[3] / "ansible" / "playbooks"


@dataclass(frozen=True)
class PlaybookResult:
    """Result of an Ansible playbook run."""

    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@dataclass
class PlaybookSpec:
    """Specification for generating an Ansible playbook."""

    name: str
    hosts: str
    strategy: str  # vendor_patch | config_workaround | compensating_control
    variables: dict = field(default_factory=dict)
    become: bool = True

    _STRATEGY_ROLE_MAP: ClassVar[dict[str, str]] = {
        "vendor_patch": "patch-package",
        "config_workaround": "config-fix",
        "compensating_control": "compensating-control",
    }

    @property
    def role_name(self) -> str:
        return self._STRATEGY_ROLE_MAP.get(self.strategy, "patch-package")


def generate_playbook(spec: PlaybookSpec) -> str:
    """Generate an Ansible playbook YAML from a PlaybookSpec."""
    playbook = [
        {
            "name": spec.name,
            "hosts": spec.hosts,
            "become": spec.become,
            "vars": spec.variables,
            "pre_tasks": [
                {
                    "name": "Run pre-checks",
                    "ansible.builtin.include_role": {"name": "pre-check"},
                }
            ],
            "roles": [
                {"role": spec.role_name},
            ],
        }
    ]

    # Use json for safe serialization, Ansible accepts JSON playbooks
    return json.dumps(playbook, indent=2)


def generate_inventory(host: str, user: str, port: int = 22, cert_file: str | None = None, private_key: str | None = None) -> str:
    """Generate a minimal Ansible inventory INI."""
    host_line = f"{host} ansible_user={user} ansible_port={port}"
    if cert_file and private_key:
        host_line += f" ansible_ssh_common_args='-o CertificateFile={cert_file} -o StrictHostKeyChecking=accept-new'"
        host_line += f" ansible_ssh_private_key_file={private_key}"
    return f"[target]\n{host_line}\n"


async def run_playbook(
    playbook_content: str,
    inventory_content: str,
    *,
    extra_vars: dict | None = None,
    timeout: int = 600,
    check_mode: bool = False,
) -> PlaybookResult:
    """Write a playbook + inventory to temp files and execute ansible-playbook."""
    with (
        tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", prefix="autopatch-pb-", delete=False,
        ) as pb_file,
        tempfile.NamedTemporaryFile(
            mode="w", suffix=".ini", prefix="autopatch-inv-", delete=False,
        ) as inv_file,
    ):
        pb_file.write(playbook_content)
        pb_path = Path(pb_file.name)
        inv_file.write(inventory_content)
        inv_path = Path(inv_file.name)

    cmd = [
        "ansible-playbook",
        str(pb_path),
        "-i", str(inv_path),
        "--timeout", str(timeout),
    ]

    if check_mode:
        cmd.append("--check")

    if extra_vars:
        cmd.extend(["--extra-vars", json.dumps(extra_vars)])

    # Point Ansible at our roles directory
    env_patch = {"ANSIBLE_ROLES_PATH": str(ANSIBLE_ROLES_DIR)}

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **env_patch},
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout + 30,
            )
        except asyncio.TimeoutError:
            proc.kill()
            return PlaybookResult(exit_code=-1, stdout="", stderr="Playbook execution timed out")

        return PlaybookResult(
            exit_code=proc.returncode or 0,
            stdout=stdout_bytes.decode(errors="replace"),
            stderr=stderr_bytes.decode(errors="replace"),
        )
    finally:
        pb_path.unlink(missing_ok=True)
        inv_path.unlink(missing_ok=True)
