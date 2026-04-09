import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.api.services.notification_service import send_webhook, dispatch_notifications


@pytest.mark.asyncio
async def test_send_webhook():
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_client.post.return_value = mock_response
    with patch("src.api.services.notification_service.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        result = await send_webhook(url="https://hooks.example.com/test", headers={}, event_type="approval_required", payload={"remediation_id": "abc"})
    assert result is True


@pytest.mark.asyncio
async def test_dispatch_notifications_filters_by_event():
    channels = [
        {"type": "webhook", "config": {"url": "https://hooks.example.com"}, "events": ["approval_required"], "enabled": True},
        {"type": "email", "config": {"addresses": ["a@b.com"]}, "events": ["remediation_completed"], "enabled": True},
    ]
    with patch("src.api.services.notification_service.send_webhook", new_callable=AsyncMock) as mock_wh:
        with patch("src.api.services.notification_service.send_email", new_callable=AsyncMock) as mock_email:
            mock_wh.return_value = True
            await dispatch_notifications(channels, "approval_required", {"test": True})
    mock_wh.assert_called_once()
    mock_email.assert_not_called()
