import json
from unittest.mock import AsyncMock, patch
import pytest
from src.api.services.event_publisher import publish_event, build_event


def test_build_node_event():
    event = build_event(remediation_id="abc-123", level="node", node_name="executor", event_type="started", payload={"duration": 0})
    assert event["level"] == "node"
    assert event["node_name"] == "executor"
    assert event["event_type"] == "started"
    assert "timestamp" in event


@pytest.mark.asyncio
async def test_publish_event_calls_redis():
    mock_redis = AsyncMock()
    event = build_event("abc-123", "node", "executor", "started", {})
    with patch("src.api.services.event_publisher.redis_client", mock_redis):
        await publish_event("abc-123", event)
    mock_redis.publish.assert_called_once()
    channel = mock_redis.publish.call_args[0][0]
    assert channel == "remediation:abc-123:events"
