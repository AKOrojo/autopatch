"""Server-Sent Events endpoint for live remediation log streaming."""
import json
import asyncio
import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_authenticated, get_settings
from src.api.middleware.auth import verify_token, verify_api_key
from src.api.models.remediation_event import RemediationEvent
from src.shared.redis_client import redis_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/remediations", tags=["sse"])

LEVEL_HIERARCHY = {"node": 0, "tool": 1, "llm": 2}


def _should_include(event_level: str, requested_level: str) -> bool:
    return LEVEL_HIERARCHY.get(event_level, 0) <= LEVEL_HIERARCHY.get(requested_level, 0)


async def _get_stored_events(session: AsyncSession, remediation_id: str, level: str) -> list[dict]:
    query = select(RemediationEvent).where(RemediationEvent.remediation_id == remediation_id).order_by(RemediationEvent.created_at)
    result = await session.execute(query)
    events = []
    for e in result.scalars().all():
        if _should_include(e.level, level):
            events.append({"level": e.level, "node_name": e.node_name, "event_type": e.event_type,
                "payload": e.payload, "timestamp": e.created_at.isoformat() if e.created_at else None})
    return events


async def _subscribe_to_live_events(remediation_id: str, level: str):
    pubsub = redis_client.pubsub()
    channel = f"remediation:{remediation_id}:events"
    await pubsub.subscribe(channel)
    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message["type"] == "message":
                event = json.loads(message["data"])
                if _should_include(event.get("level", "node"), level):
                    yield event
            await asyncio.sleep(0.1)
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.close()


async def _event_stream(session: AsyncSession, remediation_id: str, level: str, request: Request):
    stored = await _get_stored_events(session, remediation_id, level)
    for event in stored:
        yield f"event: {event['level']}\ndata: {json.dumps(event, default=str)}\n\n"
    async for event in _subscribe_to_live_events(remediation_id, level):
        if await request.is_disconnected():
            break
        yield f"event: {event.get('level', 'node')}\ndata: {json.dumps(event, default=str)}\n\n"


@router.get("/{remediation_id}/stream")
async def stream_remediation_events(remediation_id: str, request: Request,
    level: str = Query("node", pattern="^(node|tool|llm)$"),
    token: str | None = Query(None),
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings)):
    # SSE auth: accept token query param (EventSource can't send headers)
    if token:
        verify_token(token, settings)
    else:
        # Fall back to header-based auth
        from src.api.dependencies import get_authenticated
        get_authenticated(request, settings)
    return StreamingResponse(_event_stream(session, remediation_id, level, request),
        media_type="text/event-stream", headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})
