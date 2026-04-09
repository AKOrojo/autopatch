from unittest.mock import AsyncMock, patch
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.api.routes.audit_logs import router


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


def test_list_audit_logs_returns_200(client):
    with patch("src.api.routes.audit_logs._query_audit_logs", new_callable=AsyncMock, return_value={"data": [], "total": 0, "page": 1, "per_page": 50}):
        response = client.get("/api/v1/audit-logs")
    assert response.status_code == 200
    assert response.json()["data"] == []
