from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/v1/remediations", tags=["remediations"])

@router.get("")
async def list_remediations():
    return JSONResponse(status_code=status.HTTP_501_NOT_IMPLEMENTED, content={"detail": "Not implemented yet"})
