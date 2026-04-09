from unittest.mock import AsyncMock, patch
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
    from src.api.dependencies import get_authenticated, get_db
    app.dependency_overrides[get_authenticated] = lambda: {"auth_type": "api_key"}
    app.dependency_overrides[get_db] = lambda: AsyncMock()
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
            response = client.get("/api/v1/remediations/test-id/stream?level=node", headers={"Accept": "text/event-stream"})
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
