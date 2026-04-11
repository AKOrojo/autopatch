"""Tests for container logs endpoints."""
import json

import pytest
from unittest.mock import patch, MagicMock


@pytest.mark.asyncio
async def test_get_containers(client, api_key_headers):
    mock_containers = [
        {"name": "autopatch-api-1", "service": "api", "state": "running",
         "status": "Up 2 hours", "health": "healthy", "ports": [], "image": "autopatch-api"},
        {"name": "autopatch-celery-worker-1", "service": "celery-worker", "state": "running",
         "status": "Up 2 hours", "health": "", "ports": [], "image": "autopatch-api"},
    ]
    with patch("src.api.routes.system_status._get_containers", return_value=mock_containers):
        resp = await client.get("/api/v1/system/containers", headers=api_key_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert data[0]["service"] == "api"
    assert data[0]["state"] == "running"
    assert "ports" not in data[0]  # containers endpoint should not include ports


def _make_mock_container(service="api", name="autopatch-api-1", status="running", log_lines=None):
    """Helper to build a mock Docker container object."""
    container = MagicMock()
    container.name = name
    container.status = status
    container.labels = {
        "com.docker.compose.project": "autopatch",
        "com.docker.compose.service": service,
    }
    if log_lines is not None:
        container.logs.return_value = iter(
            [line.encode("utf-8") for line in log_lines]
        )
    return container


@pytest.mark.asyncio
async def test_stream_logs_unknown_service(client, api_key_headers):
    """Requesting logs for a service that doesn't exist should return 404."""
    mock_client = MagicMock()
    mock_client.containers.list.return_value = [
        _make_mock_container(service="api"),
    ]
    with patch("src.api.routes.system_status.docker") as mock_docker:
        mock_docker.from_env.return_value = mock_client
        resp = await client.get(
            "/api/v1/system/logs/nonexistent?follow=false",
            headers=api_key_headers,
        )
    assert resp.status_code == 404
    assert "nonexistent" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_stream_logs_returns_sse(client, api_key_headers):
    """Verify the endpoint returns text/event-stream with log data."""
    log_lines = [
        "2026-04-10T12:00:00.000Z INFO  Starting server\n",
        "2026-04-10T12:00:01.000Z DEBUG  Ready\n",
    ]
    mock_container = _make_mock_container(service="api", log_lines=log_lines)
    mock_client = MagicMock()
    mock_client.containers.list.return_value = [mock_container]

    with patch("src.api.routes.system_status.docker") as mock_docker:
        mock_docker.from_env.return_value = mock_client
        resp = await client.get(
            "/api/v1/system/logs/api?follow=false",
            headers=api_key_headers,
        )

    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]

    body = resp.text
    # Should contain the connected event
    assert "event: connected" in body
    # Should contain our log content
    assert "Starting server" in body
    assert "Ready" in body


@pytest.mark.asyncio
async def test_stream_logs_search_filter(client, api_key_headers):
    """When search param is set, only matching lines should appear."""
    log_lines = [
        "2026-04-10T12:00:00.000Z INFO  All good\n",
        "2026-04-10T12:00:01.000Z ERROR  Something broke\n",
        "2026-04-10T12:00:02.000Z INFO  Still fine\n",
    ]
    mock_container = _make_mock_container(service="api", log_lines=log_lines)
    mock_client = MagicMock()
    mock_client.containers.list.return_value = [mock_container]

    with patch("src.api.routes.system_status.docker") as mock_docker:
        mock_docker.from_env.return_value = mock_client
        resp = await client.get(
            "/api/v1/system/logs/api?follow=false&search=ERROR",
            headers=api_key_headers,
        )

    assert resp.status_code == 200
    body = resp.text
    # The ERROR line should be present
    assert "Something broke" in body
    # The non-matching lines should NOT be present
    assert "All good" not in body
    assert "Still fine" not in body
