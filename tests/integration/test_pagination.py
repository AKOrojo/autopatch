import pytest

@pytest.mark.asyncio
async def test_assets_pagination(client, api_key_headers):
    for i in range(3):
        await client.post("/api/v1/assets", json={"hostname": f"page-test-{i}", "ip_address": f"10.99.{i}.1"}, headers=api_key_headers)
    resp = await client.get("/api/v1/assets?limit=2&offset=0", headers=api_key_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) <= 2
    assert "x-total-count" in resp.headers

@pytest.mark.asyncio
async def test_vulnerabilities_pagination(client, api_key_headers):
    resp = await client.get("/api/v1/vulnerabilities?limit=10&offset=0", headers=api_key_headers)
    assert resp.status_code == 200
    assert "x-total-count" in resp.headers

@pytest.mark.asyncio
async def test_scans_pagination(client, api_key_headers):
    resp = await client.get("/api/v1/scans?limit=10&offset=0", headers=api_key_headers)
    assert resp.status_code == 200
    assert "x-total-count" in resp.headers
