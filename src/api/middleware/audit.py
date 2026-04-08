import hashlib
import json

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.models.audit_log import AuditLog


async def compute_checksum(session: AsyncSession, action_detail: dict) -> str:
    result = await session.execute(select(AuditLog.checksum).order_by(desc(AuditLog.id)).limit(1))
    prev_checksum = result.scalar_one_or_none() or "genesis"
    data = prev_checksum + json.dumps(action_detail, sort_keys=True, default=str)
    return hashlib.sha256(data.encode()).hexdigest()


async def write_audit_log(
    session: AsyncSession,
    event_type: str,
    action_detail: dict,
    user_id: str | None = None,
    ip_address: str | None = None,
    asset_id: str | None = None,
    vulnerability_id: str | None = None,
    remediation_id: str | None = None,
    agent_id: str | None = None,
    model_id: str | None = None,
    reasoning_chain: str | None = None,
    pre_state: dict | None = None,
    post_state: dict | None = None,
) -> AuditLog:
    checksum = await compute_checksum(session, action_detail)
    entry = AuditLog(
        event_type=event_type,
        action_detail=action_detail,
        user_id=user_id,
        ip_address=ip_address,
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
        remediation_id=remediation_id,
        agent_id=agent_id,
        model_id=model_id,
        reasoning_chain=reasoning_chain,
        pre_state=pre_state,
        post_state=post_state,
        checksum=checksum,
    )
    session.add(entry)
    await session.flush()
    return entry
