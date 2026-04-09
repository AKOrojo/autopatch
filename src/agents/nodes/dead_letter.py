# src/agents/nodes/dead_letter.py
"""Dead letter node — bundles artifacts, notifies, destroys clone."""

from __future__ import annotations

import logging
from typing import Any

from src.agents.state import AutopatchState
from src.shared.minio_client import get_minio_client, ensure_bucket, upload_json, upload_text
from src.shared.notification import notify_dead_letter
from src.api.services.clone_service import CloneService

logger = logging.getLogger(__name__)


async def dead_letter_node(state: AutopatchState) -> dict[str, Any]:
    """Handle remediation that exhausted all retries."""
    vuln_id = state.get("vulnerability_id", "unknown")
    reason = state.get("dead_letter_reason", "unknown")
    base_path = f"dead_letter/{vuln_id}"

    artifact_path = ""
    try:
        client = get_minio_client()
        bucket = "autopatch"
        ensure_bucket(client, bucket)

        upload_json(client, bucket, f"{base_path}/strategy_history.json",
                    state.get("strategy_history", []))
        upload_json(client, bucket, f"{base_path}/verification_reports.json",
                    state.get("verification_results", {}))
        upload_json(client, bucket, f"{base_path}/execution_result.json",
                    state.get("execution_result", {}))

        summary_lines = [
            f"# Dead Letter Report: {vuln_id}",
            f"CVE: {state.get('cve_id', 'N/A')}",
            f"Reason: {reason}",
            f"Total attempts: {state.get('total_attempts', 0)}",
            f"Strategy history:",
        ]
        for entry in state.get("strategy_history", []):
            summary_lines.append(f"  - {entry.get('strategy')}: {entry.get('error', 'unknown')}")
        upload_text(client, bucket, f"{base_path}/summary.md", "\n".join(summary_lines))

        artifact_path = f"{bucket}/{base_path}/"
        logger.info("Dead letter artifacts uploaded to %s", artifact_path)

    except Exception as exc:
        logger.exception("Failed to upload dead letter artifacts: %s", exc)

    try:
        strategies_tried = [e.get("strategy", "") for e in state.get("strategy_history", [])]
        last_error = ""
        if state.get("strategy_history"):
            last_error = state["strategy_history"][-1].get("error", "")

        await notify_dead_letter(
            vulnerability_id=vuln_id,
            cve_id=state.get("cve_id"),
            asset_id=state.get("asset_id", ""),
            severity=state.get("scan_data", {}).get("severity", "unknown"),
            attempts=state.get("total_attempts", 0),
            strategies_tried=strategies_tried,
            last_error=last_error,
            artifact_path=artifact_path,
        )
    except Exception as exc:
        logger.exception("Dead letter notification failed: %s", exc)

    try:
        plan = state.get("remediation_plan", {})
        clone_name = plan.get("clone_name", "")
        if clone_name:
            svc = CloneService()
            result = svc.destroy_clone(clone_name)
            if not result.success:
                logger.error("Clone destruction failed: %s", result.error)
            else:
                logger.info("Clone %s destroyed", clone_name)
    except Exception as exc:
        logger.exception("Clone destruction error: %s", exc)

    return {
        "status": "dead_letter",
        "artifact_bundle_path": artifact_path,
    }
