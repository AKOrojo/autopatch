import uuid
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.dependencies import get_db, get_authenticated
from src.api.models.vulnerability import Vulnerability
from src.api.schemas.vulnerability import VulnerabilityResponse, VulnerabilityUpdate
from src.shared.exceptions import NotFoundError

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])

@router.get("", response_model=list[VulnerabilityResponse])
async def list_vulnerabilities(
    response: Response,
    status: str | None = Query(None),
    severity: str | None = Query(None),
    asset_id: uuid.UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(get_authenticated),
):
    count_query = select(func.count()).select_from(Vulnerability)
    if status:
        count_query = count_query.where(Vulnerability.status == status)
    if severity:
        count_query = count_query.where(Vulnerability.severity == severity)
    if asset_id:
        count_query = count_query.where(Vulnerability.asset_id == asset_id)
    count_result = await db.execute(count_query)
    total = count_result.scalar()
    response.headers["X-Total-Count"] = str(total)

    query = select(Vulnerability)
    if status:
        query = query.where(Vulnerability.status == status)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)
    query = query.order_by(Vulnerability.priority_score.desc().nulls_last()).limit(limit).offset(offset)
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(vuln_id: uuid.UUID, db: AsyncSession = Depends(get_db), auth: dict = Depends(get_authenticated)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise NotFoundError(detail=f"Vulnerability {vuln_id} not found")
    return vuln

@router.patch("/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(vuln_id: uuid.UUID, payload: VulnerabilityUpdate, db: AsyncSession = Depends(get_db), auth: dict = Depends(get_authenticated)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise NotFoundError(detail=f"Vulnerability {vuln_id} not found")
    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(vuln, field, value)
    await db.commit()
    await db.refresh(vuln)
    return vuln
