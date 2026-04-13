"""OpenVAS backend using python-gvm over TLS."""
import xml.etree.ElementTree as ET
from contextlib import contextmanager

from src.api.config import Settings
from src.api.services.scanners.parser import parse_openvas_results

_STATUS_MAP = {
    "Done": "completed",
    "Running": "running",
    "Requested": "pending",
    "Queued": "pending",
    "Stop Requested": "pending",
    "Stopped": "failed",
    "Internal Error": "failed",
}


class OpenVASBackend:
    @contextmanager
    def _gmp_session(self):
        """Yield an authenticated, version-negotiated GMP connection."""
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import Gmp

        settings = Settings()
        connection = TLSConnection(
            hostname=settings.gmp_host, port=settings.gmp_port
        )
        with Gmp(connection=connection) as gmp:
            gmp.authenticate(settings.gmp_username, settings.gmp_password)
            yield gmp

    def _extract_id(self, xml_response: str) -> str:
        """Extract the id attribute from the root element of an XML response."""
        root = ET.fromstring(xml_response)
        return root.get("id", "")

    def _extract_status(self, xml_response: str) -> str:
        """Parse task XML and map GMP status to our internal status string."""
        root = ET.fromstring(xml_response)
        status_el = root.find(".//task/status")
        if status_el is None:
            return "unknown"
        gmp_status = status_el.text or ""
        return _STATUS_MAP.get(gmp_status, "unknown")

    def _extract_progress(self, xml_response: str) -> int:
        """Parse task XML and return progress percentage (0-100)."""
        root = ET.fromstring(xml_response)
        progress_el = root.find(".//task/progress")
        if progress_el is None:
            return 0
        try:
            return max(0, min(100, int(progress_el.text or "0")))
        except ValueError:
            return 0

    def _extract_status_and_progress(self, xml_response: str) -> tuple[str, int]:
        """Return (status, progress) from a single task XML response."""
        return self._extract_status(xml_response), self._extract_progress(xml_response)

    async def start_scan(self, target: str, config: dict) -> str:
        with self._gmp_session() as gmp:
            target_resp = gmp.create_target(
                name=f"autopatch-{target}", hosts=[target]
            )
            target_id = self._extract_id(target_resp)

            task_resp = gmp.create_task(
                name=f"autopatch-scan-{target}",
                config_id=config.get(
                    "config_id", "daba56c8-73ec-11df-a475-002264764cea"
                ),
                target_id=target_id,
                scanner_id=config.get(
                    "scanner_id", "08b69003-5fc2-4037-a479-93b440211c73"
                ),
            )
            task_id = self._extract_id(task_resp)

            gmp.start_task(task_id)
            return task_id

    async def get_scan_status(self, scanner_task_id: str) -> str:
        with self._gmp_session() as gmp:
            task_resp = gmp.get_task(scanner_task_id)
            return self._extract_status(task_resp)

    async def get_scan_status_and_progress(self, scanner_task_id: str) -> tuple[str, int]:
        """Single GMP call returning (status, progress_pct)."""
        with self._gmp_session() as gmp:
            task_resp = gmp.get_task(scanner_task_id)
            return self._extract_status_and_progress(task_resp)

    async def get_results(self, scanner_task_id: str) -> list[dict]:
        with self._gmp_session() as gmp:
            xml_results = gmp.get_results(task_id=scanner_task_id)
            return parse_openvas_results(xml_results)

    async def configure_alert(self, scanner_task_id: str, webhook_url: str) -> None:
        from gvm.protocols.gmp.requests.v224._alerts import (
            AlertCondition,
            AlertEvent,
            AlertMethod,
        )

        with self._gmp_session() as gmp:
            gmp.create_alert(
                name=f"autopatch-alert-{scanner_task_id}",
                condition=AlertCondition.ALWAYS,
                event=AlertEvent.TASK_RUN_STATUS_CHANGED,
                event_data={"status": "Done"},
                method=AlertMethod.HTTP_GET,
                method_data={"URL": webhook_url},
            )
