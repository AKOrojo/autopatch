"""Remediation pipeline tasks — runs the LangGraph analysis workflow."""
import asyncio
import logging
import time

from src.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


def _load_approval_context(asset_id):
    from src.api.config import Settings
    from src.shared.database import init_engine, async_session_factory
    from src.api.models.asset import Asset
    from src.api.models.approval_policy import ApprovalPolicy
    from sqlalchemy import select

    settings = Settings()
    if not async_session_factory:
        init_engine(settings.database_url)

    async def _run():
        async with async_session_factory() as session:
            result = await session.execute(select(Asset).where(Asset.id == asset_id))
            asset = result.scalar_one_or_none()
            tier = asset.tier if asset else "dev"
            result = await session.execute(select(ApprovalPolicy).where(ApprovalPolicy.asset_tier == tier))
            policy = result.scalar_one_or_none()
            policy_dict = {
                "max_auto_approve_cvss": policy.max_auto_approve_cvss if policy else 7.0,
                "auto_approve_config_only": policy.auto_approve_config_only if policy else True,
                "require_approval_for_service_restart": policy.require_approval_for_service_restart if policy else True,
            }
            return tier, policy_dict, settings.global_mode
    return asyncio.run(_run())


def _persist_event(remediation_id, level, node_name, event_type, payload):
    from src.shared.database import init_engine, async_session_factory
    from src.api.models.remediation_event import RemediationEvent
    from src.api.services.event_publisher import build_event, publish_event
    from src.api.config import Settings

    settings = Settings()
    if not async_session_factory:
        init_engine(settings.database_url)

    event = build_event(remediation_id, level, node_name, event_type, payload)

    async def _run():
        from src.shared.redis_client import init_redis, redis_client
        if not redis_client:
            init_redis(settings.redis_url)
        async with async_session_factory() as session:
            row = RemediationEvent(remediation_id=remediation_id, level=level, node_name=node_name, event_type=event_type, payload=payload)
            session.add(row)
            await session.commit()
        await publish_event(remediation_id, event)
    asyncio.run(_run())


def _create_approval_request(remediation_id, asset_id, cvss_score, asset_tier, auto_approved):
    from src.shared.database import init_engine, async_session_factory
    from src.api.models.approval_request import ApprovalRequest
    from src.api.config import Settings

    settings = Settings()
    if not async_session_factory:
        init_engine(settings.database_url)

    async def _run():
        async with async_session_factory() as session:
            ar = ApprovalRequest(remediation_id=remediation_id, asset_id=asset_id, risk_score=cvss_score or 0.0,
                asset_tier=asset_tier, auto_approved=auto_approved, status="approved" if auto_approved else "pending")
            session.add(ar)
            await session.flush()
            ar_id = str(ar.id)
            await session.commit()
            return ar_id
    return asyncio.run(_run())


def _poll_approval(approval_request_id, timeout=3600, interval=10):
    from src.shared.database import init_engine, async_session_factory
    from src.api.models.approval_request import ApprovalRequest
    from src.api.config import Settings
    from sqlalchemy import select

    settings = Settings()
    if not async_session_factory:
        init_engine(settings.database_url)

    start = time.time()
    while time.time() - start < timeout:
        async def _check():
            async with async_session_factory() as session:
                result = await session.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_request_id))
                ar = result.scalar_one_or_none()
                return ar.status if ar else "rejected"
        status = asyncio.run(_check())
        if status in ("approved", "rejected"):
            return status
        time.sleep(interval)
    return "rejected"


def _run_graph_sync(vulnerability_id, asset_id, cve_id, scan_data, asset_criticality, asset_tier, approval_policy, global_mode):
    from src.agents.graph import build_graph
    from src.agents.state import make_initial_state

    state = make_initial_state(vulnerability_id=vulnerability_id, asset_id=asset_id, cve_id=cve_id,
        scan_data=scan_data, asset_criticality=asset_criticality)
    state["asset_tier"] = asset_tier
    state["approval_policy"] = approval_policy
    state["global_mode"] = global_mode

    graph = build_graph()
    result = asyncio.run(graph.ainvoke(state))
    return dict(result)


@celery_app.task(bind=True, name="src.workers.remediation_tasks.analyze_vulnerability", queue="agents", max_retries=2, default_retry_delay=30)
def analyze_vulnerability(self, vulnerability_id, asset_id, cve_id, scan_data, asset_criticality="medium"):
    logger.info("Starting analysis for vulnerability %s (CVE: %s)", vulnerability_id, cve_id)
    _persist_event(vulnerability_id, "node", "pipeline", "started", {"cve_id": cve_id})

    try:
        asset_tier, approval_policy, global_mode = _load_approval_context(asset_id)
        result = _run_graph_sync(vulnerability_id, asset_id, cve_id, scan_data, asset_criticality,
            asset_tier, approval_policy, global_mode)

        if result.get("approval_status") == "waiting":
            _persist_event(vulnerability_id, "node", "approval_gate", "waiting", {"reasons": "Manual approval required"})
            ar_id = _create_approval_request(remediation_id=vulnerability_id, asset_id=asset_id,
                cvss_score=result.get("cvss_score"), asset_tier=asset_tier, auto_approved=False)
            from src.workers.notification_tasks import send_notification
            send_notification.delay("approval_required", {"vulnerability_id": vulnerability_id,
                "asset_id": asset_id, "cvss_score": result.get("cvss_score"),
                "asset_tier": asset_tier, "approval_request_id": ar_id})
            approval_result = _poll_approval(ar_id)
            if approval_result == "rejected":
                _persist_event(vulnerability_id, "node", "approval_gate", "rejected", {})
                return {"vulnerability_id": vulnerability_id, "status": "rejected"}
            _persist_event(vulnerability_id, "node", "approval_gate", "approved", {})
            result["approval_status"] = "approved"
            from src.agents.graph import build_graph
            graph = build_graph()
            result = asyncio.run(graph.ainvoke(result))
            result = dict(result)
        elif result.get("approval_auto_approved"):
            _create_approval_request(remediation_id=vulnerability_id, asset_id=asset_id,
                cvss_score=result.get("cvss_score"), asset_tier=asset_tier, auto_approved=True)

        _persist_event(vulnerability_id, "node", "pipeline", "completed", {"status": result.get("status")})

        logger.info("Analysis complete for %s: scope=%s, strategy=%s, status=%s",
            vulnerability_id, result.get("scope_decision"), result.get("strategy"), result.get("status"))
        return {"vulnerability_id": vulnerability_id, "scope_decision": result.get("scope_decision"),
            "ssvc_decision": result.get("ssvc_decision"), "priority_score": result.get("priority_score"),
            "strategy": result.get("strategy"), "remediation_plan": result.get("remediation_plan"),
            "status": result.get("status"), "error": result.get("error")}
    except Exception as exc:
        _persist_event(vulnerability_id, "node", "pipeline", "error", {"error": str(exc)})
        logger.error("Analysis failed for %s: %s", vulnerability_id, exc)
        raise self.retry(exc=exc)
