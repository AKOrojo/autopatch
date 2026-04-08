import os
import pytest


def test_settings_loads_from_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost:5432/test")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret")
    monkeypatch.setenv("API_KEYS", "key1,key2")

    from src.api.config import Settings

    s = Settings()
    assert s.database_url == "postgresql+asyncpg://u:p@localhost:5432/test"
    assert s.redis_url == "redis://localhost:6379/0"
    assert s.jwt_secret_key == "test-secret"
    assert s.api_keys == ["key1", "key2"]
    assert s.jwt_algorithm == "HS256"
    assert s.jwt_expire_minutes == 60


def test_settings_default_values(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost:5432/test")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret")
    monkeypatch.setenv("API_KEYS", "key1")

    from src.api.config import Settings

    s = Settings()
    assert s.app_name == "Autopatch"
    assert s.debug is False
    assert s.log_level == "INFO"
