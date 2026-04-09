import os
import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("API_KEYS", "key1")

from src.agents.llm import get_llm_client, get_model_name, reset_client


def test_get_llm_client(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "http://localhost:8001/v1")
    reset_client()
    client = get_llm_client()
    assert client.base_url.host == "localhost"
    assert client.base_url.port == 8001

def test_get_model_name(monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "test-model")
    name = get_model_name()
    assert name == "test-model"
