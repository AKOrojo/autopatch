import pytest

@pytest.mark.asyncio
async def test_patch_asset(client, api_key_headers):
    create_resp = await client.post(
        "/api/v1/assets",
        json={"hostname": "patch-test", "ip_address": "10.0.99.1"},
        headers=api_key_headers,
    )
    assert create_resp.status_code == 201
    asset_id = create_resp.json()["id"]
    patch_resp = await client.patch(
        f"/api/v1/assets/{asset_id}",
        json={"criticality": "critical", "ssh_port": 2222},
        headers=api_key_headers,
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["criticality"] == "critical"
    assert patch_resp.json()["ssh_port"] == 2222

@pytest.mark.asyncio
async def test_get_asset_scans(client, api_key_headers):
    create_resp = await client.post(
        "/api/v1/assets",
        json={"hostname": "scan-list-test", "ip_address": "10.0.99.2"},
        headers=api_key_headers,
    )
    asset_id = create_resp.json()["id"]
    resp = await client.get(f"/api/v1/assets/{asset_id}/scans", headers=api_key_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

@pytest.mark.asyncio
async def test_get_asset_vulnerabilities(client, api_key_headers):
    create_resp = await client.post(
        "/api/v1/assets",
        json={"hostname": "vuln-list-test", "ip_address": "10.0.99.3"},
        headers=api_key_headers,
    )
    asset_id = create_resp.json()["id"]
    resp = await client.get(f"/api/v1/assets/{asset_id}/vulnerabilities", headers=api_key_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
