import pytest

@pytest.mark.asyncio
async def test_create_asset(client, api_key_headers):
    response = await client.post("/api/v1/assets", json={"hostname": "web-01", "ip_address": "10.0.1.5", "os_family": "ubuntu", "os_version": "22.04", "environment": "production", "criticality": "high"}, headers=api_key_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["hostname"] == "web-01"
    assert "id" in data

@pytest.mark.asyncio
async def test_list_assets(client, api_key_headers):
    response = await client.get("/api/v1/assets", headers=api_key_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

@pytest.mark.asyncio
async def test_get_asset_not_found(client, api_key_headers):
    response = await client.get("/api/v1/assets/00000000-0000-0000-0000-000000000000", headers=api_key_headers)
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_unauthenticated_request(client):
    response = await client.get("/api/v1/assets")
    assert response.status_code == 401
