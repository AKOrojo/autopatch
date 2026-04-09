"""Trivy vulnerability scanner tool — filesystem and image scanning.

Attempts to run trivy locally first, falls back to Docker if the binary
is not found.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

TRIVY_DOCKER_IMAGE = "aquasec/trivy:latest"


@dataclass
class TrivyResult:
    exit_code: int
    vulnerabilities: list[dict] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""

    @property
    def cve_ids(self) -> set[str]:
        return {v.get("VulnerabilityID", "") for v in self.vulnerabilities if v.get("VulnerabilityID")}


async def run_trivy_scan(
    target: str,
    *,
    scan_type: str = "fs",
    severity: str = "CRITICAL,HIGH",
    timeout: int = 300,
) -> TrivyResult:
    """Run a Trivy scan. Falls back to Docker if trivy binary not found."""
    use_docker = shutil.which("trivy") is None

    if use_docker:
        logger.info("trivy not found locally, using Docker image %s", TRIVY_DOCKER_IMAGE)
        cmd = [
            "docker", "run", "--rm", "--network=host",
            TRIVY_DOCKER_IMAGE,
            scan_type, "--format", "json", "--severity", severity, "--quiet", target,
        ]
    else:
        cmd = ["trivy", scan_type, "--format", "json", "--severity", severity, "--quiet", target]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except (asyncio.TimeoutError, TimeoutError):
            proc.kill()
            return TrivyResult(exit_code=-1, stderr="Trivy scan timeout")

        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")

        vulns = []
        if stdout.strip():
            try:
                data = json.loads(stdout)
                for result in data.get("Results", []):
                    for vuln in result.get("Vulnerabilities", []):
                        vulns.append(vuln)
            except json.JSONDecodeError:
                pass

        return TrivyResult(exit_code=proc.returncode or 0, vulnerabilities=vulns, stdout=stdout, stderr=stderr)

    except FileNotFoundError:
        binary = "docker" if use_docker else "trivy"
        return TrivyResult(exit_code=-1, stderr=f"{binary} binary not found")
    except Exception as e:
        return TrivyResult(exit_code=-1, stderr=str(e))
