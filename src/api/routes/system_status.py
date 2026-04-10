import asyncio
import json
import sys

import httpx
from fastapi import APIRouter, Depends
from src.api.dependencies import get_authenticated

router = APIRouter(prefix="/api/v1/system", tags=["system"])


async def _get_containers_via_socket() -> list[dict] | None:
    """Query Docker Engine API over the Unix socket (Linux containers)."""
    socket_path = "/var/run/docker.sock"
    try:
        transport = httpx.AsyncHTTPTransport(uds=socket_path)
        async with httpx.AsyncClient(transport=transport, base_url="http://docker") as client:
            resp = await client.get("/containers/json", params={"all": "true"}, timeout=5.0)
            resp.raise_for_status()
            raw = resp.json()

        containers = []
        for c in raw:
            ports = []
            for p in c.get("Ports") or []:
                if p.get("PublicPort"):
                    ports.append({
                        "PublishedPort": p["PublicPort"],
                        "TargetPort": p["PrivatePort"],
                        "Protocol": p.get("Type", "tcp"),
                    })

            labels = c.get("Labels", {})
            service = labels.get("com.docker.compose.service", "")
            status_str = c.get("Status", "")
            state = c.get("State", "unknown")
            health = ""
            if "healthy" in status_str.lower():
                health = "healthy"
            elif "unhealthy" in status_str.lower():
                health = "unhealthy"

            containers.append({
                "name": (c.get("Names") or ["/unknown"])[0].lstrip("/"),
                "service": service,
                "state": state,
                "status": status_str,
                "health": health,
                "ports": ports,
                "image": c.get("Image", ""),
            })
        return containers
    except Exception:
        return None


async def _get_containers_via_cli() -> list[dict] | None:
    """Fallback: use docker compose ps CLI."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "compose", "ps", "--format", "json", "--all",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        if proc.returncode != 0:
            return None

        containers = []
        for line in stdout.decode().strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                health = data.get("Health", "")
                status_str = data.get("Status", "")
                state = data.get("State", "unknown")

                ports = []
                for p in data.get("Publishers") or []:
                    if p.get("PublishedPort"):
                        ports.append({
                            "PublishedPort": p["PublishedPort"],
                            "TargetPort": p["TargetPort"],
                            "Protocol": p.get("Protocol", "tcp"),
                        })

                containers.append({
                    "name": data.get("Name", ""),
                    "service": data.get("Service", ""),
                    "state": state,
                    "status": status_str,
                    "health": health,
                    "ports": ports,
                    "image": data.get("Image", ""),
                })
            except json.JSONDecodeError:
                continue
        return containers
    except Exception:
        return None


async def _get_containers_via_pipe() -> list[dict] | None:
    """Windows: query Docker Engine API via named pipe."""
    if sys.platform != "win32":
        return None
    try:
        # On Windows, use TCP Docker API (Docker Desktop exposes on localhost:2375 if enabled)
        async with httpx.AsyncClient(base_url="http://localhost:2375") as client:
            resp = await client.get("/containers/json", params={"all": "true"}, timeout=5.0)
            resp.raise_for_status()
            raw = resp.json()

        containers = []
        for c in raw:
            ports = []
            for p in c.get("Ports") or []:
                if p.get("PublicPort"):
                    ports.append({
                        "PublishedPort": p["PublicPort"],
                        "TargetPort": p["PrivatePort"],
                        "Protocol": p.get("Type", "tcp"),
                    })

            labels = c.get("Labels", {})
            service = labels.get("com.docker.compose.service", "")
            status_str = c.get("Status", "")
            state = c.get("State", "unknown")
            health = ""
            if "healthy" in status_str.lower():
                health = "healthy"
            elif "unhealthy" in status_str.lower():
                health = "unhealthy"

            containers.append({
                "name": (c.get("Names") or ["/unknown"])[0].lstrip("/"),
                "service": service,
                "state": state,
                "status": status_str,
                "health": health,
                "ports": ports,
                "image": c.get("Image", ""),
            })
        return containers
    except Exception:
        return None


async def _run_docker_ps() -> list[dict]:
    """Try all available methods to get container list."""
    containers = await _get_containers_via_socket()
    if containers is None:
        containers = await _get_containers_via_cli()
    if containers is None:
        containers = await _get_containers_via_pipe()
    return containers or []


@router.get("/containers")
async def get_containers(auth: dict = Depends(get_authenticated)):
    """Return a lightweight list of container names and states."""
    containers = await _run_docker_ps()
    return [
        {"name": c["name"], "service": c["service"], "state": c["state"]}
        for c in containers
    ]


@router.get("/status")
async def get_system_status(auth: dict = Depends(get_authenticated)):
    """Return status of all Docker containers. Tries multiple methods."""
    containers = await _run_docker_ps()

    running = sum(1 for c in containers if c["state"] == "running")
    return {
        "containers": containers,
        "summary": {
            "total": len(containers),
            "running": running,
            "stopped": len(containers) - running,
        },
    }
