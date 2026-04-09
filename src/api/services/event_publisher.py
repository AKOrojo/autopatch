"""Redis pub/sub event publishing for remediation streaming."""
import json
from datetime import datetime, timezone
from src.shared.redis_client import redis_client


def build_event(remediation_id: str, level: str, node_name: str, event_type: str, payload: dict) -> dict:
    return {"remediation_id": remediation_id, "level": level, "node_name": node_name,
        "event_type": event_type, "payload": payload, "timestamp": datetime.now(timezone.utc).isoformat()}


async def publish_event(remediation_id: str, event: dict) -> None:
    channel = f"remediation:{remediation_id}:events"
    await redis_client.publish(channel, json.dumps(event, default=str))
