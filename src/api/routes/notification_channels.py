"""Notification channel management API — admin only."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, require_admin
from src.api.middleware.audit import write_audit_log
from src.api.models.notification_channel import NotificationChannel
from src.api.models.user import User

router = APIRouter(prefix="/api/v1/notification-channels", tags=["notifications"])


class ChannelRequest(BaseModel):
    type: str
    config: dict
    events: list[str]
    enabled: bool = True


def _channel_to_dict(c: NotificationChannel) -> dict:
    return {"id": str(c.id), "type": c.type, "config": c.config, "events": c.events,
        "enabled": c.enabled, "created_by": str(c.created_by),
        "created_at": c.created_at.isoformat() if c.created_at else None}


async def _list_channels(session: AsyncSession) -> list[dict]:
    result = await session.execute(select(NotificationChannel).order_by(NotificationChannel.created_at.desc()))
    return [_channel_to_dict(c) for c in result.scalars().all()]


@router.get("")
async def list_channels(admin: User = Depends(require_admin), session: AsyncSession = Depends(get_db)):
    return await _list_channels(session)


@router.post("", status_code=201)
async def create_channel(body: ChannelRequest, admin: User = Depends(require_admin), session: AsyncSession = Depends(get_db)):
    if body.type not in ("email", "webhook"):
        raise HTTPException(status_code=400, detail="Invalid channel type")
    channel = NotificationChannel(type=body.type, config=body.config, events=body.events, enabled=body.enabled, created_by=admin.id)
    session.add(channel)
    await write_audit_log(session, "channel_created", {"type": body.type}, user_id=str(admin.id))
    await session.flush()
    await session.commit()
    return _channel_to_dict(channel)


@router.put("/{channel_id}")
async def update_channel(channel_id: str, body: ChannelRequest, admin: User = Depends(require_admin), session: AsyncSession = Depends(get_db)):
    result = await session.execute(select(NotificationChannel).where(NotificationChannel.id == channel_id))
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    channel.type = body.type
    channel.config = body.config
    channel.events = body.events
    channel.enabled = body.enabled
    await write_audit_log(session, "channel_updated", {"channel_id": channel_id}, user_id=str(admin.id))
    await session.commit()
    return _channel_to_dict(channel)


@router.delete("/{channel_id}", status_code=204)
async def delete_channel(channel_id: str, admin: User = Depends(require_admin), session: AsyncSession = Depends(get_db)):
    result = await session.execute(select(NotificationChannel).where(NotificationChannel.id == channel_id))
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    await session.delete(channel)
    await write_audit_log(session, "channel_deleted", {"channel_id": channel_id, "type": channel.type}, user_id=str(admin.id))
    await session.commit()


@router.post("/{channel_id}/test")
async def test_channel(channel_id: str, admin: User = Depends(require_admin), session: AsyncSession = Depends(get_db)):
    result = await session.execute(select(NotificationChannel).where(NotificationChannel.id == channel_id))
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    from src.workers.notification_tasks import send_notification
    send_notification.delay("test", {"message": "Test notification from Autopatch", "channel_id": str(channel.id)})
    return {"status": "test_queued"}
