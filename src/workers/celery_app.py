from celery import Celery
from src.api.config import Settings

settings = Settings()

celery_app = Celery(
    "autopatch",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_routes={
        "src.workers.scan_tasks.*": {"queue": "scans"},
    },
    beat_schedule={
        "poll-openvas-scans": {
            "task": "src.workers.scan_tasks.poll_openvas_scans",
            "schedule": 60.0,
        },
    },
)

celery_app.autodiscover_tasks(["src.workers"])
