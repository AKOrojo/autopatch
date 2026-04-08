from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])

@router.get("")
async def list_reports():
    return JSONResponse(status_code=status.HTTP_501_NOT_IMPLEMENTED, content={"detail": "Not implemented yet"})
