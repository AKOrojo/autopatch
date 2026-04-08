import pytest
from unittest.mock import patch

@pytest.mark.asyncio
async def test_sync_enrichment(client, api_key_headers):
    with patch("src.api.routes.enrichment.sync_all_enrichment") as mock_sync:
        mock_sync.delay = lambda: None
        response = await client.post("/api/v1/enrichment/sync", headers=api_key_headers)
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"

@pytest.mark.asyncio
async def test_sync_enrichment_requires_auth(client):
    response = await client.post("/api/v1/enrichment/sync")
    assert response.status_code == 401
