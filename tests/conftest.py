import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://autopatch:autopatch_dev@localhost:5432/autopatch_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing")
os.environ.setdefault("API_KEYS", "test-api-key-1,test-api-key-2")

from src.api.config import Settings
from src.shared import database
from src.shared.redis_client import init_redis
from src.api.main import app


@pytest.fixture
def api_key_headers():
    return {"X-API-Key": "test-api-key-1"}


@pytest_asyncio.fixture
async def client():
    """Create a fresh DB engine per test to avoid event loop issues."""
    settings = Settings()
    # Force re-create engine on the current event loop
    database.engine = None
    database.async_session_factory = None
    database.init_engine(settings.database_url)
    init_redis(settings.redis_url)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    await database.close_engine()
    database.engine = None
    database.async_session_factory = None
