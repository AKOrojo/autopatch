import uuid
from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.dependencies import get_db, get_authenticated
from src.api.models.asset import Asset
from src.api.schemas.asset import AssetCreate, AssetResponse
from src.api.middleware.audit import write_audit_log
from src.shared.exceptions import NotFoundError

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])

@router.get("", response_model=list[AssetResponse])
async def list_assets(db: AsyncSession = Depends(get_db), auth: dict = Depends(get_authenticated)):
    result = await db.execute(select(Asset).order_by(Asset.created_at.desc()))
    return result.scalars().all()

@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(payload: AssetCreate, db: AsyncSession = Depends(get_db), auth: dict = Depends(get_authenticated)):
    asset = Asset(**payload.model_dump())
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    await write_audit_log(session=db, event_type="asset_registered", action_detail={"hostname": asset.hostname, "ip_address": asset.ip_address}, asset_id=str(asset.id), user_id=auth.get("sub"))
    await db.commit()
    return asset

@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: uuid.UUID, db: AsyncSession = Depends(get_db), auth: dict = Depends(get_authenticated)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise NotFoundError(detail=f"Asset {asset_id} not found")
    return asset

@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(asset_id: uuid.UUID, db: AsyncSession = Depends(get_db), auth: dict = Depends(get_authenticated)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise NotFoundError(detail=f"Asset {asset_id} not found")
    await db.delete(asset)
    await db.commit()
    await write_audit_log(session=db, event_type="asset_deregistered", action_detail={"hostname": asset.hostname, "ip_address": asset.ip_address}, asset_id=str(asset_id), user_id=auth.get("sub"))
    await db.commit()
