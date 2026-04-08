import logging
from fastapi import APIRouter, Query, status
from fastapi.responses import JSONResponse
from src.workers.scan_tasks import ingest_results

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans/webhook", tags=["webhooks"])

@router.get("/openvas")
async def openvas_webhook(scan_id: str = Query(None)):
    if not scan_id:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "scan_id query parameter required"},
        )
    logger.info(f"OpenVAS webhook received for scan {scan_id}")
    ingest_results.delay(scan_id)
    return {"status": "accepted", "scan_id": scan_id}
