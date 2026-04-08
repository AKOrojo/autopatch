"""Trivy backend using Docker SDK."""
import uuid

import docker

from src.api.services.scanners.parser import parse_trivy_results

TRIVY_IMAGE = "aquasec/trivy:0.58.2"

_results_cache: dict[str, list[dict]] = {}
_status_cache: dict[str, str] = {}


class TrivyBackend:
    async def start_scan(self, target: str, config: dict) -> str:
        image_name = config.get("image")
        if not image_name:
            raise ValueError("config must contain 'image' key specifying the image to scan")

        client = docker.from_env()
        cmd = f"image --format json --quiet {image_name}"
        container = client.containers.run(
            TRIVY_IMAGE,
            cmd,
            detach=True,
            network_mode="host",
            remove=False,
            volumes={"/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "ro"}},
        )
        container.wait()
        logs = container.logs().decode("utf-8", errors="replace")
        results = parse_trivy_results(logs)
        scan_id = str(uuid.uuid4())
        _results_cache[scan_id] = results
        _status_cache[scan_id] = "completed"
        return scan_id

    async def get_scan_status(self, scanner_task_id: str) -> str:
        return _status_cache.get(scanner_task_id, "unknown")

    async def get_results(self, scanner_task_id: str) -> list[dict]:
        return _results_cache.get(scanner_task_id, [])

    async def configure_alert(self, scanner_task_id: str, webhook_url: str) -> None:
        raise NotImplementedError("Trivy does not support webhook alerts natively")
