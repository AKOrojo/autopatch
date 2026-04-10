"""Tests for container logs endpoints."""
import pytest
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_get_containers(client, api_key_headers):
    mock_containers = [
        {"name": "autopatch-api-1", "service": "api", "state": "running",
         "status": "Up 2 hours", "health": "healthy", "ports": [], "image": "autopatch-api"},
        {"name": "autopatch-celery-worker-1", "service": "celery-worker", "state": "running",
         "status": "Up 2 hours", "health": "", "ports": [], "image": "autopatch-api"},
    ]
    with patch("src.api.routes.system_status._run_docker_ps", new_callable=AsyncMock, return_value=mock_containers):
        resp = await client.get("/api/v1/system/containers", headers=api_key_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert data[0]["service"] == "api"
    assert data[0]["state"] == "running"
    assert "ports" not in data[0]  # containers endpoint should not include ports
