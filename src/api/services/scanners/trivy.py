class TrivyBackend:
    async def start_scan(self, target: str, config: dict) -> str:
        raise NotImplementedError
    async def get_scan_status(self, scanner_task_id: str) -> str:
        raise NotImplementedError
    async def get_results(self, scanner_task_id: str) -> list[dict]:
        raise NotImplementedError
    async def configure_alert(self, scanner_task_id: str, webhook_url: str) -> None:
        raise NotImplementedError
