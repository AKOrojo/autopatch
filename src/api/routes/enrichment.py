from fastapi import APIRouter, Depends
from src.api.dependencies import get_authenticated
from src.workers.enrichment_tasks import sync_all_enrichment

router = APIRouter(prefix="/api/v1/enrichment", tags=["enrichment"])

@router.post("/sync")
async def trigger_sync(auth: dict = Depends(get_authenticated)):
    sync_all_enrichment.delay()
    return {"status": "accepted"}
