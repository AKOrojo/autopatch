import pytest
from unittest.mock import patch

@pytest.mark.asyncio
async def test_openvas_webhook_dispatches_ingest(client):
    with patch("src.api.routes.webhooks.ingest_results") as mock_ingest:
        mock_ingest.delay = lambda x: None
        response = await client.get("/api/v1/scans/webhook/openvas?scan_id=test-scan-123")
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"

@pytest.mark.asyncio
async def test_openvas_webhook_missing_scan_id(client):
    response = await client.get("/api/v1/scans/webhook/openvas")
    assert response.status_code == 400
