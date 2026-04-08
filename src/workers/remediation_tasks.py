"""Remediation pipeline tasks — runs the LangGraph analysis workflow."""

import asyncio
import logging

from src.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


def _run_graph_sync(vulnerability_id, asset_id, cve_id, scan_data, asset_criticality):
    """Run the LangGraph workflow synchronously (for Celery)."""
    from src.agents.graph import build_graph
    from src.agents.state import make_initial_state

    state = make_initial_state(
        vulnerability_id=vulnerability_id,
        asset_id=asset_id,
        cve_id=cve_id,
        scan_data=scan_data,
        asset_criticality=asset_criticality,
    )

    graph = build_graph()
    result = asyncio.run(graph.ainvoke(state))
    return dict(result)


@celery_app.task(bind=True, name="src.workers.remediation_tasks.analyze_vulnerability", queue="agents", max_retries=2, default_retry_delay=30)
def analyze_vulnerability(self, vulnerability_id, asset_id, cve_id, scan_data, asset_criticality="medium"):
    """Analyze a vulnerability through the full agent pipeline."""
    logger.info("Starting analysis for vulnerability %s (CVE: %s)", vulnerability_id, cve_id)
    try:
        result = _run_graph_sync(vulnerability_id, asset_id, cve_id, scan_data, asset_criticality)
        logger.info(
            "Analysis complete for %s: scope=%s, strategy=%s, status=%s",
            vulnerability_id, result.get("scope_decision"), result.get("strategy"), result.get("status"),
        )
        return {
            "vulnerability_id": vulnerability_id,
            "scope_decision": result.get("scope_decision"),
            "ssvc_decision": result.get("ssvc_decision"),
            "priority_score": result.get("priority_score"),
            "strategy": result.get("strategy"),
            "remediation_plan": result.get("remediation_plan"),
            "status": result.get("status"),
            "error": result.get("error"),
        }
    except Exception as exc:
        logger.error("Analysis failed for %s: %s", vulnerability_id, exc)
        raise self.retry(exc=exc)
