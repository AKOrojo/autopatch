"""Nuclei backend using Docker SDK."""
import uuid

import docker

from src.api.services.scanners.parser import parse_nuclei_results

NUCLEI_IMAGE = "projectdiscovery/nuclei:v3.4.3"

_results_cache: dict[str, list[dict]] = {}
_status_cache: dict[str, str] = {}


class NucleiBackend:
    async def start_scan(self, target: str, config: dict) -> str:
        client = docker.from_env()
        urls = config.get("urls") or [f"https://{target}:8006", f"https://{target}", f"http://{target}"]
        url_args = " ".join(f"-u {u}" for u in urls)
        cmd = f"{url_args} -jsonl -silent"
        container = client.containers.run(
            NUCLEI_IMAGE,
            cmd,
            detach=True,
            remove=False,
        )
        container.wait()
        logs = container.logs().decode("utf-8", errors="replace")
        results = parse_nuclei_results(logs)
        scan_id = str(uuid.uuid4())
        _results_cache[scan_id] = results
        _status_cache[scan_id] = "completed"
        return scan_id

    async def get_scan_status(self, scanner_task_id: str) -> str:
        return _status_cache.get(scanner_task_id, "unknown")

    async def get_results(self, scanner_task_id: str) -> list[dict]:
        return _results_cache.get(scanner_task_id, [])

    async def configure_alert(self, scanner_task_id: str, webhook_url: str) -> None:
        raise NotImplementedError("Nuclei does not support webhook alerts natively")
