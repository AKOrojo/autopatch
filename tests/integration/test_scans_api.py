import pytest

@pytest.mark.asyncio
async def test_create_scan_requires_auth(client):
    response = await client.post("/api/v1/scans", json={})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_list_scans(client, api_key_headers):
    response = await client.get("/api/v1/scans", headers=api_key_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
