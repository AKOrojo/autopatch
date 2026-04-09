"""Dashboard overview API."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.dependencies import get_db, get_authenticated
from src.api.services.dashboard_service import compute_date_range, get_overview

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/overview")
async def overview(range: str | None = Query("30d", pattern="^(7d|30d|90d)$"),
    start: str | None = Query(None), end: str | None = Query(None),
    _auth=Depends(get_authenticated), session: AsyncSession = Depends(get_db)):
    start_dt, end_dt = compute_date_range(range, start, end)
    return await get_overview(session, start_dt, end_dt)
