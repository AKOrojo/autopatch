"""Webhook notification sender for dead-letter and alerting."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


async def send_webhook(url: str, payload: dict, timeout: int = 10) -> bool:
    """Send a JSON webhook notification. Returns True on success."""
    if not url:
        logger.warning("No webhook URL configured, skipping notification")
        return False

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=payload,
                timeout=timeout,
                headers={"Content-Type": "application/json"},
            )
            if response.status_code < 300:
                logger.info("Webhook sent successfully to %s", url)
                return True
            logger.warning("Webhook returned %d: %s", response.status_code, response.text[:200])
            return False
    except Exception as e:
        logger.exception("Webhook send failed: %s", e)
        return False


async def notify_dead_letter(
    vulnerability_id: str,
    cve_id: str | None,
    asset_id: str,
    severity: str,
    attempts: int,
    strategies_tried: list[str],
    last_error: str,
    artifact_path: str,
) -> bool:
    """Send a dead-letter notification via webhook."""
    from src.api.config import Settings
    settings = Settings()

    payload = {
        "event": "dead_letter",
        "vulnerability_id": vulnerability_id,
        "cve_id": cve_id,
        "asset_id": asset_id,
        "severity": severity,
        "total_attempts": attempts,
        "strategies_tried": strategies_tried,
        "last_error": last_error[:500],
        "artifact_bundle": artifact_path,
    }
    return await send_webhook(settings.notification_webhook_url, payload)
