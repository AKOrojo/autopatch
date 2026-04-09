"""Dashboard KPI and chart data aggregation."""
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, func, and_, extract
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.models.vulnerability import Vulnerability
from src.api.models.approval_request import ApprovalRequest
from src.api.models.remediation_event import RemediationEvent

RANGE_MAP = {"7d": 7, "30d": 30, "90d": 90}


def compute_date_range(range_str: str | None, start_str: str | None = None, end_str: str | None = None, end_override: datetime | None = None) -> tuple[datetime, datetime]:
    if start_str and end_str:
        return (datetime.fromisoformat(start_str.replace("Z", "+00:00")), datetime.fromisoformat(end_str.replace("Z", "+00:00")))
    end = end_override or datetime.now(timezone.utc)
    days = RANGE_MAP.get(range_str or "30d", 30)
    return end - timedelta(days=days), end


async def _compute_success_rate(session: AsyncSession, start: datetime, end: datetime) -> float:
    """Percentage of remediations that completed with status 'remediated' vs total completed."""
    total_result = await session.execute(
        select(func.count(func.distinct(RemediationEvent.remediation_id)))
        .where(and_(
            RemediationEvent.node_name == "pipeline",
            RemediationEvent.event_type == "completed",
            RemediationEvent.created_at >= start,
            RemediationEvent.created_at <= end,
        ))
    )
    total = total_result.scalar() or 0
    if total == 0:
        return 0.0

    success_result = await session.execute(
        select(func.count(func.distinct(RemediationEvent.remediation_id)))
        .where(and_(
            RemediationEvent.node_name == "pipeline",
            RemediationEvent.event_type == "completed",
            RemediationEvent.payload["status"].as_string() == "remediated",
            RemediationEvent.created_at >= start,
            RemediationEvent.created_at <= end,
        ))
    )
    successes = success_result.scalar() or 0
    return round((successes / total) * 100, 1)


async def _compute_mttr(session: AsyncSession, start: datetime, end: datetime) -> float:
    """Mean time to remediate in hours — avg time between pipeline started and completed events."""
    from sqlalchemy.orm import aliased

    started = aliased(RemediationEvent)
    completed = aliased(RemediationEvent)

    # Get pairs of started/completed events for the same remediation
    started_sub = (
        select(started.remediation_id, func.min(started.created_at).label("started_at"))
        .where(and_(started.node_name == "pipeline", started.event_type == "started",
                     started.created_at >= start, started.created_at <= end))
        .group_by(started.remediation_id)
        .subquery()
    )

    completed_sub = (
        select(completed.remediation_id, func.max(completed.created_at).label("completed_at"))
        .where(and_(completed.node_name == "pipeline", completed.event_type == "completed",
                     completed.created_at >= start, completed.created_at <= end))
        .group_by(completed.remediation_id)
        .subquery()
    )

    result = await session.execute(
        select(func.avg(
            extract("epoch", completed_sub.c.completed_at) - extract("epoch", started_sub.c.started_at)
        ))
        .select_from(started_sub.join(completed_sub, started_sub.c.remediation_id == completed_sub.c.remediation_id))
    )
    avg_seconds = result.scalar()
    if avg_seconds is None:
        return 0.0
    return round(avg_seconds / 3600, 1)


async def get_overview(session: AsyncSession, start: datetime, end: datetime) -> dict:
    open_count_result = await session.execute(select(func.count(Vulnerability.id)).where(Vulnerability.status == "open"))
    open_vulns = open_count_result.scalar() or 0

    prev_open_result = await session.execute(
        select(func.count(Vulnerability.id)).where(and_(Vulnerability.status == "open", Vulnerability.created_at <= start)))
    prev_open = prev_open_result.scalar() or 0

    pending_result = await session.execute(select(func.count(ApprovalRequest.id)).where(ApprovalRequest.status == "pending"))
    pending_approvals = pending_result.scalar() or 0

    severity_result = await session.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .where(and_(Vulnerability.status == "open", Vulnerability.created_at >= start, Vulnerability.created_at <= end))
        .group_by(Vulnerability.severity))
    vulns_by_severity = {row[0]: row[1] for row in severity_result.all()}

    success_rate = await _compute_success_rate(session, start, end)
    mttr_hours = await _compute_mttr(session, start, end)

    return {
        "kpi": {"open_vulnerabilities": open_vulns, "open_vulns_delta": open_vulns - prev_open,
            "pending_approvals": pending_approvals, "success_rate": success_rate, "mttr_hours": mttr_hours},
        "charts": {"vulns_by_severity": vulns_by_severity},
    }
