import docker
from fastapi import APIRouter, Depends
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
