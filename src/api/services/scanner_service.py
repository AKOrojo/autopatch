from typing import Protocol, runtime_checkable

@runtime_checkable
class ScannerBackend(Protocol):
    async def start_scan(self, target: str, config: dict) -> str:
        ...
    async def get_scan_status(self, scanner_task_id: str) -> str:
        ...
    async def get_results(self, scanner_task_id: str) -> list[dict]:
        ...
    async def configure_alert(self, scanner_task_id: str, webhook_url: str) -> None:
        ...

def get_scanner_backend(scanner_type: str) -> ScannerBackend:
    from src.api.services.scanners.openvas import OpenVASBackend
    from src.api.services.scanners.nuclei import NucleiBackend
    backends = {
        "openvas": OpenVASBackend,
        "nuclei": NucleiBackend,
    }
    cls = backends.get(scanner_type)
    if cls is None:
        raise ValueError(f"Unknown scanner type: {scanner_type}")
    return cls()
