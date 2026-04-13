"""Nuclei backend using Docker SDK."""
import re
import threading
import uuid
from collections.abc import Callable

import docker

from src.api.services.scanners.parser import parse_nuclei_results

NUCLEI_IMAGE = "projectdiscovery/nuclei:v3.4.3"

_results_cache: dict[str, list[dict]] = {}
_status_cache: dict[str, str] = {}
_progress_cache: dict[str, int] = {}


def _parse_nuclei_progress(line: str) -> int | None:
    """
    Parse a nuclei stats line and return a progress percentage.

    Nuclei v3 stats lines look like:
      [INF] ... | Requests: 45 / 200 [22%] ...
    or without the bracketed percentage:
      [INF] ... | Requests: 45 / 200 ...
    """
    # Prefer the explicit [N%] marker
    match = re.search(r"\[(\d{1,3})%\]", line)
    if match:
        return max(0, min(100, int(match.group(1))))
    # Fallback: compute from "Requests: done / total"
    match = re.search(r"Requests:\s*(\d+)\s*/\s*(\d+)", line)
    if match:
        done, total = int(match.group(1)), int(match.group(2))
        if total > 0:
            return max(0, min(100, int(done / total * 100)))
    return None


class NucleiBackend:
    async def start_scan(
        self,
        target: str,
        config: dict,
        progress_callback: Callable[[int], None] | None = None,
    ) -> str:
        client = docker.from_env()
        urls = config.get("urls") or [
            f"https://{target}:8006",
            f"https://{target}",
            f"http://{target}",
        ]
        url_args = " ".join(f"-u {u}" for u in urls)
        # -stats/-stats-interval emit periodic progress lines to stderr
        cmd = f"{url_args} -jsonl -silent -stats -stats-interval 5"
        container = client.containers.run(
            NUCLEI_IMAGE,
            cmd,
            detach=True,
            network_mode="host",
            remove=False,
        )
        scan_id = str(uuid.uuid4())
        _status_cache[scan_id] = "running"
        _progress_cache[scan_id] = 0

        # Stream stderr in a daemon thread to parse progress while the
        # main thread blocks on container.wait().
        def _stream_stats() -> None:
            try:
                for chunk in container.logs(
                    stream=True, follow=True, stdout=False, stderr=True
                ):
                    line = chunk.decode("utf-8", errors="replace").strip()
                    pct = _parse_nuclei_progress(line)
                    if pct is not None:
                        _progress_cache[scan_id] = pct
                        if progress_callback:
                            try:
                                progress_callback(pct)
                            except Exception:
                                pass
            except Exception:
                pass

        threading.Thread(target=_stream_stats, daemon=True).start()

        container.wait()
        logs = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
        results = parse_nuclei_results(logs)
        _results_cache[scan_id] = results
        _status_cache[scan_id] = "completed"
        _progress_cache[scan_id] = 100
        if progress_callback:
            try:
                progress_callback(100)
            except Exception:
                pass
        return scan_id

    async def get_scan_status(self, scanner_task_id: str) -> str:
        return _status_cache.get(scanner_task_id, "unknown")

    async def get_results(self, scanner_task_id: str) -> list[dict]:
        return _results_cache.get(scanner_task_id, [])

    async def configure_alert(self, scanner_task_id: str, webhook_url: str) -> None:
        raise NotImplementedError("Nuclei does not support webhook alerts natively")
