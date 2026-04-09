"""Dashboard KPI and chart data aggregation."""
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.models.vulnerability import Vulnerability
from src.api.models.approval_request import ApprovalRequest

RANGE_MAP = {"7d": 7, "30d": 30, "90d": 90}


def compute_date_range(range_str: str | None, start_str: str | None = None, end_str: str | None = None, end_override: datetime | None = None) -> tuple[datetime, datetime]:
    if start_str and end_str:
        return (datetime.fromisoformat(start_str.replace("Z", "+00:00")), datetime.fromisoformat(end_str.replace("Z", "+00:00")))
    end = end_override or datetime.now(timezone.utc)
    days = RANGE_MAP.get(range_str or "30d", 30)
    return end - timedelta(days=days), end


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

    return {
        "kpi": {"open_vulnerabilities": open_vulns, "open_vulns_delta": open_vulns - prev_open,
            "pending_approvals": pending_approvals, "success_rate": 0.0, "mttr_hours": 0.0},
        "charts": {"vulns_by_severity": vulns_by_severity},
    }
