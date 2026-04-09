import uuid
from unittest.mock import AsyncMock
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.api.routes.settings_routes import router
from src.api.models.user import User


@pytest.fixture
def app():
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def client(app):
    from src.api.dependencies import require_admin, get_db
    admin = User(id=uuid.UUID("00000000-0000-0000-0000-000000000001"), email="admin@test.com", password_hash="x", name="Admin", role="admin", is_active=True)
    app.dependency_overrides[require_admin] = lambda: admin
    app.dependency_overrides[get_db] = lambda: AsyncMock()
    return TestClient(app)


def test_get_settings(client):
    response = client.get("/api/v1/settings")
    assert response.status_code == 200
    data = response.json()
    assert "global_mode" in data
