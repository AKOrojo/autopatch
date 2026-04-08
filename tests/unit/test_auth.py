import os
import pytest
from datetime import timedelta
from jose import jwt

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key")
os.environ.setdefault("API_KEYS", "test-api-key-1,test-api-key-2")

from src.api.middleware.auth import create_access_token, verify_token, verify_api_key
from src.api.config import Settings


@pytest.fixture
def settings():
    return Settings()


def test_create_access_token(settings):
    token = create_access_token(data={"sub": "admin"}, settings=settings)
    assert isinstance(token, str)
    parts = token.split(".")
    assert len(parts) == 3


def test_verify_token_valid(settings):
    token = create_access_token(data={"sub": "admin"}, settings=settings)
    payload = verify_token(token, settings)
    assert payload["sub"] == "admin"
    assert "exp" in payload


def test_verify_token_expired(settings):
    token = create_access_token(data={"sub": "admin"}, settings=settings, expires_delta=timedelta(seconds=-1))
    with pytest.raises(Exception):
        verify_token(token, settings)


def test_verify_token_invalid(settings):
    with pytest.raises(Exception):
        verify_token("not.a.valid.token", settings)


def test_verify_api_key_valid(settings):
    assert verify_api_key("test-api-key-1", settings) is True
    assert verify_api_key("test-api-key-2", settings) is True


def test_verify_api_key_invalid(settings):
    assert verify_api_key("wrong-key", settings) is False
    assert verify_api_key("", settings) is False
