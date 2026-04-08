import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

os.environ["DATABASE_URL"] = "postgresql+asyncpg://autopatch:autopatch_dev@localhost:5432/autopatch_test"
os.environ["REDIS_URL"] = "redis://localhost:6379/1"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-testing"
os.environ["API_KEYS"] = "test-api-key"

from src.api.main import app

@pytest.fixture
def api_key_headers():
    return {"X-API-Key": "test-api-key"}

@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
