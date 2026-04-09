from unittest.mock import AsyncMock, patch, MagicMock
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.api.routes.sse import router


@pytest.fixture
def app():
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def client(app):
    from src.api.dependencies import get_db, get_settings
    app.dependency_overrides[get_db] = lambda: AsyncMock()
    # Provide mock settings for token verification
    mock_settings = MagicMock()
    mock_settings.api_keys = ["test-key"]
    app.dependency_overrides[get_settings] = lambda: mock_settings
    return TestClient(app)


def test_sse_endpoint_returns_event_stream(client):
    stored_events = []
    async def mock_get_stored(*args, **kwargs):
        return stored_events
    with patch("src.api.routes.sse._get_stored_events", mock_get_stored):
        with patch("src.api.routes.sse._subscribe_to_live_events") as mock_sub:
            async def empty_gen(*args, **kwargs):
                return
                yield
            mock_sub.return_value = empty_gen()
            # Use API key header for auth
            response = client.get("/api/v1/remediations/test-id/stream?level=node",
                headers={"Accept": "text/event-stream", "X-API-Key": "test-key"})
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
