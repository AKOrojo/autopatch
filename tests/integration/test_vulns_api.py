import pytest

@pytest.mark.asyncio
async def test_list_vulnerabilities(client, api_key_headers):
    response = await client.get("/api/v1/vulnerabilities", headers=api_key_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

@pytest.mark.asyncio
async def test_get_vulnerability_not_found(client, api_key_headers):
    response = await client.get("/api/v1/vulnerabilities/00000000-0000-0000-0000-000000000000", headers=api_key_headers)
    assert response.status_code == 404
