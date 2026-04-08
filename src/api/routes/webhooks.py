from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

@router.post("/{scanner}")
async def receive_webhook(scanner: str):
    return JSONResponse(status_code=status.HTTP_501_NOT_IMPLEMENTED, content={"detail": "Not implemented yet"})
