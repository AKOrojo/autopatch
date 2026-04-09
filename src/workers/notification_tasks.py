"""Notification Celery tasks — dispatch email and webhook notifications."""
import asyncio
import logging
from src.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_channels_and_dispatch(event_type, payload):
    from src.api.config import Settings
    from src.shared.database import init_engine, async_session_factory
    from src.api.models.notification_channel import NotificationChannel
    from src.api.services.notification_service import dispatch_notifications
    from sqlalchemy import select

    settings = Settings()
    if not async_session_factory:
        init_engine(settings.database_url)

    async def _run():
        async with async_session_factory() as session:
            result = await session.execute(select(NotificationChannel).where(NotificationChannel.enabled == True))
            channels = [{"type": c.type, "config": c.config, "events": c.events, "enabled": c.enabled} for c in result.scalars().all()]
        smtp_config = {"smtp_host": settings.smtp_host, "smtp_port": settings.smtp_port,
            "smtp_username": settings.smtp_username, "smtp_password": settings.smtp_password,
            "from_email": settings.smtp_from_email} if settings.smtp_host else None
        await dispatch_notifications(channels, event_type, payload, smtp_config)

    asyncio.run(_run())


@celery_app.task(name="src.workers.notification_tasks.send_notification", queue="scans")
def send_notification(event_type: str, payload: dict):
    logger.info("Dispatching notifications for event: %s", event_type)
    try:
        _get_channels_and_dispatch(event_type, payload)
    except Exception as e:
        logger.error("Notification dispatch failed: %s", e)
