import asyncio
import json
import re
from typing import Optional

import docker
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from src.api.dependencies import get_authenticated

router = APIRouter(prefix="/api/v1/system", tags=["system"])


def _get_containers() -> list[dict]:
    """List containers via Docker SDK (requires /var/run/docker.sock mount)."""
    try:
        client = docker.from_env()
        containers = []
        for c in client.containers.list(all=True):
            labels = c.labels or {}
            # Filter to only autopatch project containers
            project = labels.get("com.docker.compose.project", "")
            if project != "autopatch":
                continue

            health = ""
            if c.attrs.get("State", {}).get("Health"):
                health = c.attrs["State"]["Health"].get("Status", "")

            # Build ports list matching the frontend's expected shape
            ports = []
            for container_port, bindings in (c.ports or {}).items():
                target_port = int(container_port.split("/")[0])
                if bindings:
                    for b in bindings:
                        ports.append({
                            "TargetPort": target_port,
                            "PublishedPort": int(b.get("HostPort", 0)),
                        })
                else:
                    ports.append({"TargetPort": target_port, "PublishedPort": 0})

            containers.append({
                "name": c.name or "",
                "service": labels.get("com.docker.compose.service", ""),
                "state": c.status,  # running, exited, etc.
                "status": c.attrs.get("State", {}).get("Status", ""),
                "health": health,
                "ports": ports,
                "image": ",".join(c.image.tags) if c.image.tags else c.image.short_id,
            })
        return containers
    except Exception:
        return []


@router.get("/containers")
async def get_containers(auth: dict = Depends(get_authenticated)):
    """Return a lightweight list of container names and states."""
    containers = _get_containers()
    return [
        {"name": c["name"], "service": c["service"], "state": c["state"]}
        for c in containers
    ]


@router.get("/status")
async def get_system_status(auth: dict = Depends(get_authenticated)):
    """Return status of all Docker Compose services."""
    containers = _get_containers()
    running = sum(1 for c in containers if c["state"] == "running")
    return {
        "containers": containers,
        "summary": {
            "total": len(containers),
            "running": running,
            "stopped": len(containers) - running,
        },
    }


_STDERR_PATTERN = re.compile(r"\b(ERROR|FATAL|CRITICAL|PANIC)\b", re.IGNORECASE)


def _find_container_by_service(service_name: str):
    """Find a Docker container whose compose service label matches *service_name*."""
    client = docker.from_env()
    for c in client.containers.list(all=True):
        labels = c.labels or {}
        if labels.get("com.docker.compose.project") != "autopatch":
            continue
        if labels.get("com.docker.compose.service") == service_name:
            return c
    return None


def _sync_log_generator(container, tail, follow, search, since, until):
    """Yield raw log lines from the Docker SDK (blocking generator)."""
    kwargs: dict = {
        "stream": True,
        "follow": follow,
        "tail": tail,
        "timestamps": True,
    }
    if since:
        kwargs["since"] = since
    if until:
        kwargs["until"] = until

    for chunk in container.logs(**kwargs):
        line = chunk.decode("utf-8", errors="replace").rstrip("\n")
        if not line:
            continue
        if search and search.lower() not in line.lower():
            continue
        yield line


@router.get("/logs/{service_name}")
async def stream_logs(
    service_name: str,
    request: Request,
    tail: int = Query(200, ge=1, le=10000),
    search: Optional[str] = Query(None),
    since: Optional[str] = Query(None),
    until: Optional[str] = Query(None),
    follow: bool = Query(True),
    auth: dict = Depends(get_authenticated),
):
    """Stream Docker container logs as Server-Sent Events."""
    container = await asyncio.to_thread(_find_container_by_service, service_name)
    if container is None:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=404,
            content={"detail": f"Service '{service_name}' not found"},
        )

    async def _event_stream():
        # Send initial connected event with container metadata
        connected_payload = json.dumps({
            "service": service_name,
            "container": container.name,
            "state": container.status,
        })
        yield f"event: connected\ndata: {connected_payload}\n\n"

        # Stream log lines from a thread so we don't block the event loop
        gen = _sync_log_generator(container, tail, follow, search, since, until)
        queue: asyncio.Queue = asyncio.Queue()
        sentinel = object()

        def _reader():
            try:
                for line in gen:
                    queue.put_nowait(line)
            except Exception:
                pass
            finally:
                queue.put_nowait(sentinel)

        reader_task = asyncio.get_event_loop().run_in_executor(None, _reader)

        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    # Send keepalive comment
                    yield ": keepalive\n\n"
                    continue

                if item is sentinel:
                    break

                line = item
                # Parse timestamp from Docker log prefix (ISO format before first space)
                timestamp = ""
                rest = line
                if len(line) > 30 and line[4] == "-":
                    parts = line.split(" ", 1)
                    if len(parts) == 2:
                        timestamp = parts[0]
                        rest = parts[1]

                stream_type = "stderr" if _STDERR_PATTERN.search(rest) else "stdout"

                payload = json.dumps({
                    "line": rest,
                    "timestamp": timestamp,
                    "stream": stream_type,
                })
                yield f"data: {payload}\n\n"
        finally:
            # Ensure background reader finishes
            reader_task.cancel() if hasattr(reader_task, "cancel") else None

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
