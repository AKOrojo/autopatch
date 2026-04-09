"""Notification dispatch — email and webhook."""
import json
import logging
import httpx

logger = logging.getLogger(__name__)


async def send_webhook(url: str, headers: dict, event_type: str, payload: dict) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json={"event": event_type, "data": payload},
                headers={"Content-Type": "application/json", **headers})
            return response.status_code < 400
    except Exception as e:
        logger.error("Webhook delivery failed to %s: %s", url, e)
        return False


async def send_email(addresses: list[str], subject: str, body: str,
    smtp_host: str, smtp_port: int, smtp_username: str, smtp_password: str, from_email: str) -> bool:
    try:
        import aiosmtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["From"] = from_email
        msg["To"] = ", ".join(addresses)
        msg["Subject"] = subject
        msg.set_content(body)
        await aiosmtplib.send(msg, hostname=smtp_host, port=smtp_port,
            username=smtp_username if smtp_username else None,
            password=smtp_password if smtp_password else None,
            start_tls=True if smtp_username else False)
        return True
    except Exception as e:
        logger.error("Email delivery failed: %s", e)
        return False


async def dispatch_notifications(channels: list[dict], event_type: str, payload: dict, smtp_config: dict | None = None) -> None:
    for channel in channels:
        if not channel.get("enabled", True):
            continue
        if event_type not in channel.get("events", []):
            continue
        config = channel.get("config", {})
        if channel["type"] == "webhook":
            await send_webhook(url=config.get("url", ""), headers=config.get("headers", {}), event_type=event_type, payload=payload)
        elif channel["type"] == "email" and smtp_config:
            await send_email(addresses=config.get("addresses", []), subject=f"[Autopatch] {event_type}",
                body=json.dumps(payload, indent=2, default=str), **smtp_config)
