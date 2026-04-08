import uuid

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_authenticated
from src.api.models.asset import Asset
from src.api.schemas.asset import AssetCreate, AssetResponse, AssetUpdate
from src.api.models.scan import Scan
from src.api.models.vulnerability import Vulnerability
from src.api.schemas.scan import ScanResponse
from src.api.schemas.vulnerability import VulnerabilityResponse
from src.api.middleware.audit import write_audit_log
from src.shared.exceptions import NotFoundError

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


@router.get("", response_model=list[AssetResponse])
async def list_assets(
    response: Response,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(get_authenticated),
):
    count_result = await db.execute(select(func.count()).select_from(Asset))
    total = count_result.scalar()
    response.headers["X-Total-Count"] = str(total)
    result = await db.execute(select(Asset).order_by(Asset.created_at.desc()).limit(limit).offset(offset))
    return result.scalars().all()


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreate,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(get_authenticated),
):
    asset = Asset(**payload.model_dump())
    db.add(asset)
    await db.flush()
    await write_audit_log(
        session=db,
        event_type="asset_registered",
        action_detail={"hostname": asset.hostname, "ip_address": str(asset.ip_address)},
        asset_id=str(asset.id),
        user_id=auth.get("sub"),
    )
    await db.commit()
    await db.refresh(asset)
    return asset


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(get_authenticated),
):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise NotFoundError(detail=f"Asset {asset_id} not found")
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(get_authenticated),
):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise NotFoundError(detail=f"Asset {asset_id} not found")
    hostname = asset.hostname
    ip_address = str(asset.ip_address)
    await db.delete(asset)
    await write_audit_log(
        session=db,
        event_type="asset_deregistered",
        action_detail={"hostname": hostname, "ip_address": ip_address},
        asset_id=str(asset_id),
        user_id=auth.get("sub"),
    )
    await db.commit()


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(get_authenticated),
):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise NotFoundError(detail=f"Asset {asset_id} not found")
    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(asset, field, value)
    await db.commit()
    await db.refresh(asset)
    return asset


@router.get("/{asset_id}/scans", response_model=list[ScanResponse])
async def get_asset_scans(
    asset_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(get_authenticated),
):
    result = await db.execute(
        select(Scan).where(Scan.asset_id == asset_id).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    )
    return result.scalars().all()


@router.get("/{asset_id}/vulnerabilities", response_model=list[VulnerabilityResponse])
async def get_asset_vulnerabilities(
    asset_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(get_authenticated),
):
    result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.asset_id == asset_id)
        .order_by(Vulnerability.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return result.scalars().all()
