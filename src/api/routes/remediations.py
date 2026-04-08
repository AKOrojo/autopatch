"""Remediation API endpoints — trigger and monitor vulnerability analysis."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_authenticated
from src.api.models.vulnerability import Vulnerability
from src.api.models.asset import Asset

router = APIRouter(prefix="/api/v1/remediations", tags=["remediations"])


class AnalyzeRequest(BaseModel):
    vulnerability_id: str


class AnalyzeResponse(BaseModel):
    task_id: str
    vulnerability_id: str
    status: str


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_vulnerability(
    request: AnalyzeRequest,
    _auth=Depends(get_authenticated),
    session: AsyncSession = Depends(get_db),
):
    """Trigger agent-based vulnerability analysis pipeline.

    Dispatches a Celery task that runs the full LangGraph workflow:
    evaluator → research → docs → lead agent.
    """
    result = await session.execute(
        select(Vulnerability).where(Vulnerability.id == request.vulnerability_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    result = await session.execute(
        select(Asset).where(Asset.id == vuln.asset_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    scan_data = {
        "title": vuln.title,
        "severity": vuln.severity,
        "cvss_score": float(vuln.cvss_score) if vuln.cvss_score else None,
        "epss_score": float(vuln.epss_score) if vuln.epss_score else None,
        "is_kev": vuln.is_kev,
        "affected_package": vuln.affected_package,
        "affected_version": vuln.affected_version,
        "fixed_version": vuln.fixed_version,
        "os_family": asset.os_family,
        "environment": asset.environment,
    }

    from src.workers.remediation_tasks import analyze_vulnerability as analyze_task
    task = analyze_task.delay(
        vulnerability_id=str(vuln.id),
        asset_id=str(asset.id),
        cve_id=vuln.cve_id,
        scan_data=scan_data,
        asset_criticality=asset.criticality,
    )

    return AnalyzeResponse(
        task_id=task.id,
        vulnerability_id=str(vuln.id),
        status="queued",
    )


@router.get("/analyze/{task_id}")
async def get_analysis_status(task_id: str, _auth=Depends(get_authenticated)):
    """Check the status of an analysis task."""
    from celery.result import AsyncResult
    from src.workers.celery_app import celery_app

    result = AsyncResult(task_id, app=celery_app)

    response = {
        "task_id": task_id,
        "status": result.status,
    }

    if result.ready():
        if result.successful():
            response["result"] = result.result
        else:
            response["error"] = str(result.result)

    return response
