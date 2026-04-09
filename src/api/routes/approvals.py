"""Approval management API."""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, require_operator, require_admin, require_any_role
from src.api.middleware.audit import write_audit_log
from src.api.models.approval_request import ApprovalRequest
from src.api.models.approval_policy import ApprovalPolicy
from src.api.models.user import User

router = APIRouter(prefix="/api/v1", tags=["approvals"])


class ApproveRequest(BaseModel):
    reason: str | None = None


class RejectRequest(BaseModel):
    reason: str


class PolicyUpdateRequest(BaseModel):
    max_auto_approve_cvss: float | None = None
    auto_approve_config_only: bool | None = None
    require_approval_for_service_restart: bool | None = None


def _approval_to_dict(ar: ApprovalRequest) -> dict:
    return {
        "id": str(ar.id), "remediation_id": str(ar.remediation_id), "asset_id": str(ar.asset_id),
        "risk_score": ar.risk_score, "asset_tier": ar.asset_tier, "auto_approved": ar.auto_approved,
        "status": ar.status, "decided_by": str(ar.decided_by) if ar.decided_by else None,
        "decided_at": ar.decided_at.isoformat() if ar.decided_at else None,
        "reason": ar.reason, "created_at": ar.created_at.isoformat() if ar.created_at else None,
    }


@router.get("/approvals")
async def list_approvals(status: str | None = Query(None), asset_tier: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
    _user: User = Depends(require_any_role), session: AsyncSession = Depends(get_db)):
    query = select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc())
    count_query = select(func.count(ApprovalRequest.id))
    if status:
        query = query.where(ApprovalRequest.status == status)
        count_query = count_query.where(ApprovalRequest.status == status)
    if asset_tier:
        query = query.where(ApprovalRequest.asset_tier == asset_tier)
        count_query = count_query.where(ApprovalRequest.asset_tier == asset_tier)
    total = (await session.execute(count_query)).scalar() or 0
    result = await session.execute(query.limit(limit).offset(offset))
    return {"data": [_approval_to_dict(a) for a in result.scalars().all()], "total": total}


@router.get("/approvals/{approval_id}")
async def get_approval(approval_id: str, _user: User = Depends(require_any_role), session: AsyncSession = Depends(get_db)):
    result = await session.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))
    ar = result.scalar_one_or_none()
    if not ar:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return _approval_to_dict(ar)


@router.post("/approvals/{approval_id}/approve")
async def approve_request(approval_id: str, body: ApproveRequest, user: User = Depends(require_operator), session: AsyncSession = Depends(get_db)):
    result = await session.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))
    ar = result.scalar_one_or_none()
    if not ar:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if ar.status != "pending":
        raise HTTPException(status_code=409, detail=f"Approval is already {ar.status}")
    ar.status = "approved"
    ar.decided_by = user.id
    ar.decided_at = datetime.now(timezone.utc)
    ar.reason = body.reason
    await write_audit_log(session, "approval_approved", {"approval_id": approval_id, "remediation_id": str(ar.remediation_id)},
        user_id=str(user.id), remediation_id=str(ar.remediation_id), asset_id=str(ar.asset_id))
    await session.commit()
    return _approval_to_dict(ar)


@router.post("/approvals/{approval_id}/reject")
async def reject_request(approval_id: str, body: RejectRequest, user: User = Depends(require_operator), session: AsyncSession = Depends(get_db)):
    result = await session.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))
    ar = result.scalar_one_or_none()
    if not ar:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if ar.status != "pending":
        raise HTTPException(status_code=409, detail=f"Approval is already {ar.status}")
    ar.status = "rejected"
    ar.decided_by = user.id
    ar.decided_at = datetime.now(timezone.utc)
    ar.reason = body.reason
    await write_audit_log(session, "approval_rejected", {"approval_id": approval_id, "remediation_id": str(ar.remediation_id), "reason": body.reason},
        user_id=str(user.id), remediation_id=str(ar.remediation_id), asset_id=str(ar.asset_id))
    await session.commit()
    return _approval_to_dict(ar)


def _policy_to_dict(p: ApprovalPolicy) -> dict:
    return {"id": str(p.id), "asset_tier": p.asset_tier, "max_auto_approve_cvss": p.max_auto_approve_cvss,
        "auto_approve_config_only": p.auto_approve_config_only, "require_approval_for_service_restart": p.require_approval_for_service_restart}


@router.get("/approval-policies")
async def list_policies(_user: User = Depends(require_any_role), session: AsyncSession = Depends(get_db)):
    result = await session.execute(select(ApprovalPolicy).order_by(ApprovalPolicy.asset_tier))
    return [_policy_to_dict(p) for p in result.scalars().all()]


@router.put("/approval-policies/{tier}")
async def update_policy(tier: str, body: PolicyUpdateRequest, user: User = Depends(require_admin), session: AsyncSession = Depends(get_db)):
    if tier not in ("dev", "staging", "prod"):
        raise HTTPException(status_code=400, detail="Invalid tier")
    result = await session.execute(select(ApprovalPolicy).where(ApprovalPolicy.asset_tier == tier))
    policy = result.scalar_one_or_none()
    if not policy:
        policy = ApprovalPolicy(asset_tier=tier)
        session.add(policy)
    pre_state = _policy_to_dict(policy)
    if body.max_auto_approve_cvss is not None:
        policy.max_auto_approve_cvss = body.max_auto_approve_cvss
    if body.auto_approve_config_only is not None:
        policy.auto_approve_config_only = body.auto_approve_config_only
    if body.require_approval_for_service_restart is not None:
        policy.require_approval_for_service_restart = body.require_approval_for_service_restart
    await write_audit_log(session, "policy_changed", {"tier": tier}, user_id=str(user.id), pre_state=pre_state, post_state=_policy_to_dict(policy))
    await session.commit()
    return _policy_to_dict(policy)
