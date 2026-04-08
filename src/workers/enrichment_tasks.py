"""Celery tasks for CVE enrichment data imports."""
import asyncio
import logging
from src.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

@celery_app.task(name="src.workers.enrichment_tasks.import_epss")
def import_epss() -> int:
    from scripts.import_epss import run_epss_import
    return asyncio.get_event_loop().run_until_complete(run_epss_import())

@celery_app.task(name="src.workers.enrichment_tasks.import_kev")
def import_kev() -> int:
    from scripts.import_kev import run_kev_import
    return asyncio.get_event_loop().run_until_complete(run_kev_import())

@celery_app.task(name="src.workers.enrichment_tasks.import_cve_feed")
def import_cve_feed() -> int:
    from scripts.import_cve_feed import run_nvd_import
    return asyncio.get_event_loop().run_until_complete(run_nvd_import())

@celery_app.task(name="src.workers.enrichment_tasks.re_enrich_open_vulnerabilities")
def re_enrich_open_vulnerabilities() -> int:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from src.api.config import Settings
    from src.api.services.enrichment_service import re_enrich_open
    settings = Settings()
    sync_url = settings.database_url.replace("postgresql+asyncpg", "postgresql")
    engine = create_engine(sync_url)
    with Session(engine) as session:
        count = re_enrich_open(session)
    engine.dispose()
    return count

@celery_app.task(name="src.workers.enrichment_tasks.sync_all_enrichment")
def sync_all_enrichment() -> None:
    import_epss()
    import_kev()
    import_cve_feed()
    re_enrich_open_vulnerabilities()
