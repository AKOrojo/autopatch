import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("API_KEYS", "key1")
os.environ.setdefault("LLM_BASE_URL", "http://localhost:8001/v1")
os.environ.setdefault("LLM_MODEL", "test-model")

from src.agents.llm_client import get_llm_client, get_model_name

def test_get_llm_client():
    client = get_llm_client()
    assert client.base_url.host == "localhost"
    assert client.base_url.port == 8001

def test_get_model_name():
    name = get_model_name()
    assert name == "test-model"
