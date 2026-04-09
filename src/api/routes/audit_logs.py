"""Audit log viewer API with correlation and full-text search."""
import csv
import io
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func, or_, cast, String
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.dependencies import get_db, get_authenticated
from src.api.models.audit_log import AuditLog

router = APIRouter(prefix="/api/v1/audit-logs", tags=["audit"])


def _log_to_dict(log: AuditLog) -> dict:
    return {"id": log.id, "event_type": log.event_type,
        "remediation_id": str(log.remediation_id) if log.remediation_id else None,
        "vulnerability_id": str(log.vulnerability_id) if log.vulnerability_id else None,
        "asset_id": str(log.asset_id) if log.asset_id else None,
        "scan_id": str(log.scan_id) if log.scan_id else None,
        "agent_id": log.agent_id, "action_detail": log.action_detail,
        "user_id": log.user_id, "created_at": log.created_at.isoformat() if log.created_at else None}


async def _query_audit_logs(session: AsyncSession, search: str | None = None, action: str | None = None,
    user_id: str | None = None, asset_id: str | None = None, remediation_id: str | None = None,
    scan_id: str | None = None, start: str | None = None, end: str | None = None,
    page: int = 1, per_page: int = 50) -> dict:
    query = select(AuditLog).order_by(AuditLog.created_at.desc())
    count_query = select(func.count(AuditLog.id))

    if action:
        query = query.where(AuditLog.event_type == action)
        count_query = count_query.where(AuditLog.event_type == action)
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
        count_query = count_query.where(AuditLog.user_id == user_id)
    if asset_id:
        query = query.where(AuditLog.asset_id == asset_id)
        count_query = count_query.where(AuditLog.asset_id == asset_id)
    if remediation_id:
        query = query.where(AuditLog.remediation_id == remediation_id)
        count_query = count_query.where(AuditLog.remediation_id == remediation_id)
    if scan_id:
        query = query.where(AuditLog.scan_id == scan_id)
        count_query = count_query.where(AuditLog.scan_id == scan_id)
    if search:
        pattern = f"%{search}%"
        search_filter = or_(cast(AuditLog.action_detail, String).ilike(pattern),
            AuditLog.event_type.ilike(pattern), AuditLog.user_id.ilike(pattern))
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)
    if start:
        from datetime import datetime
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        query = query.where(AuditLog.created_at >= start_dt)
        count_query = count_query.where(AuditLog.created_at >= start_dt)
    if end:
        from datetime import datetime
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        query = query.where(AuditLog.created_at <= end_dt)
        count_query = count_query.where(AuditLog.created_at <= end_dt)

    total = (await session.execute(count_query)).scalar() or 0
    offset = (page - 1) * per_page
    result = await session.execute(query.limit(per_page).offset(offset))
    logs = [_log_to_dict(log) for log in result.scalars().all()]
    return {"data": logs, "total": total, "page": page, "per_page": per_page}


@router.get("")
async def list_audit_logs(search: str | None = Query(None), action: str | None = Query(None),
    user_id: str | None = Query(None), asset_id: str | None = Query(None),
    remediation_id: str | None = Query(None), scan_id: str | None = Query(None),
    start: str | None = Query(None), end: str | None = Query(None),
    page: int = Query(1, ge=1), per_page: int = Query(50, ge=1, le=200),
    _auth=Depends(get_authenticated), session: AsyncSession = Depends(get_db)):
    return await _query_audit_logs(session, search=search, action=action, user_id=user_id,
        asset_id=asset_id, remediation_id=remediation_id, scan_id=scan_id,
        start=start, end=end, page=page, per_page=per_page)


@router.get("/export")
async def export_audit_logs(search: str | None = Query(None), action: str | None = Query(None),
    user_id: str | None = Query(None), asset_id: str | None = Query(None),
    remediation_id: str | None = Query(None), scan_id: str | None = Query(None),
    start: str | None = Query(None), end: str | None = Query(None),
    _auth=Depends(get_authenticated), session: AsyncSession = Depends(get_db)):
    result = await _query_audit_logs(session, search=search, action=action, user_id=user_id,
        asset_id=asset_id, remediation_id=remediation_id, scan_id=scan_id,
        start=start, end=end, page=1, per_page=10000)
    output = io.StringIO()
    fieldnames = ["id", "created_at", "event_type", "user_id", "asset_id", "remediation_id", "scan_id", "action_detail"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in result["data"]:
        writer.writerow({k: row.get(k, "") for k in fieldnames})
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit-logs.csv"})
