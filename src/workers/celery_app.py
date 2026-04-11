from celery import Celery
from celery.schedules import crontab
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
        "src.workers.remediation_tasks.*": {"queue": "agents"},
    },
    beat_schedule={
        "poll-openvas-scans": {
            "task": "src.workers.scan_tasks.poll_openvas_scans",
            "schedule": 60.0,
        },
        "daily-epss-import": {
            "task": "src.workers.enrichment_tasks.import_epss",
            "schedule": crontab(hour=2, minute=0),
        },
        "daily-kev-import": {
            "task": "src.workers.enrichment_tasks.import_kev",
            "schedule": crontab(hour=2, minute=5),
        },
        "daily-nvd-import": {
            "task": "src.workers.enrichment_tasks.import_cve_feed",
            "schedule": crontab(hour=2, minute=10),
        },
        "daily-re-enrich": {
            "task": "src.workers.enrichment_tasks.re_enrich_open_vulnerabilities",
            "schedule": crontab(hour=2, minute=30),
        },
    },
)

celery_app.conf.include = [
    "src.workers.scan_tasks",
    "src.workers.enrichment_tasks",
    "src.workers.remediation_tasks",
    "src.workers.clone_tasks",
    "src.workers.notification_tasks",
]
