"""OpenVAS/GVM scan tool — network vulnerability scanning via GMP protocol."""

from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class OpenVASResult:
    exit_code: int
    findings: list[dict] = field(default_factory=list)
    scan_id: str = ""
    stderr: str = ""

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def has_findings(self) -> bool:
        return self.finding_count > 0


async def run_openvas_scan(
    target: str,
    *,
    gmp_host: str = "gvmd",
    gmp_port: int = 9390,
    gmp_username: str = "admin",
    gmp_password: str = "admin",
    scan_config_name: str = "Full and fast",
    timeout: int = 1800,
) -> OpenVASResult:
    base_cmd = [
        "gvm-cli", "--gmp-username", gmp_username, "--gmp-password", gmp_password,
        "socket", "--socketpath", "/run/gvmd/gvmd.sock",
    ]

    async def _gmp_command(xml_cmd: str) -> str:
        proc = await asyncio.create_subprocess_exec(
            *base_cmd, "--xml", xml_cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(f"GMP command failed: {stderr_bytes.decode()}")
        return stdout_bytes.decode(errors="replace")

    try:
        create_target_xml = (
            f'<create_target><name>autopatch-{target}</name>'
            f'<hosts>{target}</hosts>'
            f'<port_list id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"/>'
            f'</create_target>'
        )
        resp = await _gmp_command(create_target_xml)
        target_id = ET.fromstring(resp).get("id", "")
        if not target_id:
            return OpenVASResult(exit_code=-1, stderr=f"Failed to create target: {resp}")

        configs_resp = await _gmp_command('<get_configs/>')
        config_id = ""
        for config in ET.fromstring(configs_resp).findall(".//config"):
            name = config.findtext("name", "")
            if name == scan_config_name:
                config_id = config.get("id", "")
                break
        if not config_id:
            return OpenVASResult(exit_code=-1, stderr=f"Scan config '{scan_config_name}' not found")

        scanners_resp = await _gmp_command('<get_scanners/>')
        scanner_id = ""
        for scanner in ET.fromstring(scanners_resp).findall(".//scanner"):
            if scanner.findtext("name", "") == "OpenVAS Default":
                scanner_id = scanner.get("id", "")
                break

        create_task_xml = (
            f'<create_task><name>autopatch-scan-{target}</name>'
            f'<target id="{target_id}"/>'
            f'<config id="{config_id}"/>'
            f'<scanner id="{scanner_id}"/>'
            f'</create_task>'
        )
        resp = await _gmp_command(create_task_xml)
        task_id = ET.fromstring(resp).get("id", "")
        if not task_id:
            return OpenVASResult(exit_code=-1, stderr=f"Failed to create task: {resp}")

        await _gmp_command(f'<start_task task_id="{task_id}"/>')

        elapsed = 0
        poll_interval = 30
        status_resp = ""
        while elapsed < timeout:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
            status_resp = await _gmp_command(f'<get_tasks task_id="{task_id}"/>')
            status = ET.fromstring(status_resp).findtext(".//status", "")
            progress = ET.fromstring(status_resp).findtext(".//progress", "0")
            logger.info("OpenVAS scan progress: %s%% (status: %s)", progress, status)
            if status == "Done":
                break
        else:
            return OpenVASResult(exit_code=-1, stderr="OpenVAS scan timed out")

        report_elem = ET.fromstring(status_resp).find(".//last_report/report")
        report_id = report_elem.get("id", "") if report_elem is not None else ""

        results_resp = await _gmp_command(f'<get_results filter="task_id={task_id} rows=-1"/>')
        findings = []
        for result_elem in ET.fromstring(results_resp).findall(".//result"):
            finding = {
                "name": result_elem.findtext("name", ""),
                "host": result_elem.findtext("host", ""),
                "port": result_elem.findtext("port", ""),
                "severity": result_elem.findtext("severity", "0"),
                "description": result_elem.findtext("description", "")[:500],
                "nvt_oid": "",
                "cve": "",
            }
            nvt = result_elem.find("nvt")
            if nvt is not None:
                finding["nvt_oid"] = nvt.get("oid", "")
                finding["cve"] = nvt.findtext("cve", "")
            findings.append(finding)

        return OpenVASResult(exit_code=0, findings=findings, scan_id=task_id)

    except Exception as e:
        logger.exception("OpenVAS scan failed: %s", e)
        return OpenVASResult(exit_code=-1, stderr=str(e))
