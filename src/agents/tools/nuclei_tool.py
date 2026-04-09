"""Nuclei scan runner tool — template-based vulnerability verification.

Runs nuclei locally if available, otherwise via Docker container.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

NUCLEI_DOCKER_IMAGE = "projectdiscovery/nuclei:v3.7.1"


@dataclass
class NucleiResult:
    exit_code: int
    findings: list[dict] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0


async def run_nuclei_scan(
    target: str,
    *,
    template_ids: list[str] | None = None,
    severity: str | None = None,
    timeout: int = 300,
) -> NucleiResult:
    """Run a Nuclei scan. Falls back to Docker if nuclei binary not found."""
    use_docker = shutil.which("nuclei") is None

    if use_docker:
        cmd = ["docker", "run", "--rm", "--network=host", NUCLEI_DOCKER_IMAGE]
        logger.info("nuclei not found locally, using %s", NUCLEI_DOCKER_IMAGE)
    else:
        cmd = ["nuclei"]

    cmd.extend(["-target", target, "-jsonl", "-silent"])
    if template_ids:
        cmd.extend(["-template-id", ",".join(template_ids)])
    if severity:
        cmd.extend(["-severity", severity])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except (asyncio.TimeoutError, TimeoutError):
            proc.kill()
            return NucleiResult(exit_code=-1, stderr="Nuclei scan timeout")

        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")

        findings = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        return NucleiResult(exit_code=proc.returncode or 0, findings=findings, stdout=stdout, stderr=stderr)

    except FileNotFoundError:
        return NucleiResult(exit_code=-1, stderr="docker/nuclei binary not found")
    except Exception as e:
        return NucleiResult(exit_code=-1, stderr=str(e))
