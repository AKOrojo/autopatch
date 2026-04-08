import uuid
from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.dependencies import get_db, get_authenticated
from src.api.models.scan import Scan
from src.api.schemas.scan import ScanCreate, ScanResponse
from src.api.middleware.audit import write_audit_log
from src.shared.exceptions import NotFoundError

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

@router.get("", response_model=list[ScanResponse])
async def list_scans(db: AsyncSession = Depends(get_db), auth: dict = Depends(get_authenticated)):
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    return result.scalars().all()

@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(payload: ScanCreate, db: AsyncSession = Depends(get_db), auth: dict = Depends(get_authenticated)):
    scan = Scan(**payload.model_dump())
    db.add(scan)
    await db.flush()
    await write_audit_log(session=db, event_type="scan_started", action_detail={"scanner_type": scan.scanner_type, "asset_id": str(scan.asset_id)}, asset_id=str(scan.asset_id), user_id=auth.get("sub"))
    await db.commit()
    await db.refresh(scan)
    return scan

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db), auth: dict = Depends(get_authenticated)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise NotFoundError(detail=f"Scan {scan_id} not found")
    return scan
