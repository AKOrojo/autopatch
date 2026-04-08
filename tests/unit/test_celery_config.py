import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("API_KEYS", "key1")
os.environ.setdefault("CELERY_BROKER_URL", "redis://localhost:6379/1")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")


def test_celery_app_created():
    from src.workers.celery_app import celery_app
    assert celery_app.main == "autopatch"
    assert "redis" in celery_app.conf.broker_url


def test_celery_beat_schedule_exists():
    from src.workers.celery_app import celery_app
    assert "poll-openvas-scans" in celery_app.conf.beat_schedule
