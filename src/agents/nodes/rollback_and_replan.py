# src/agents/nodes/rollback_and_replan.py
"""Rollback and replan node — reverts snapshot and re-plans remediation strategy."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from src.agents.state import AutopatchState
from src.agents.nodes.retry_decision import STRATEGY_LADDER

logger = logging.getLogger(__name__)


async def rollback_and_replan_node(state: AutopatchState) -> dict:
    """Revert clone to snapshot, update retry counters, trigger re-planning."""
    from src.api.services.clone_service import CloneService

    status = state.get("status", "")
    strategy_idx = state.get("current_strategy_index", 0)
    attempt = state.get("attempt_within_strategy", 1)
    total = state.get("total_attempts", 0)
    history = list(state.get("strategy_history", []))

    # Record the failed attempt
    verification = state.get("verification_results", {})
    history.append({
        "strategy": STRATEGY_LADDER[strategy_idx] if strategy_idx < len(STRATEGY_LADDER) else "unknown",
        "attempt": attempt,
        "error": verification.get("failure_reason", "unknown"),
        "commands": state.get("execution_result", {}).get("pre_commands", []),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    # Rollback snapshot
    plan = state.get("remediation_plan", {})
    vm_id = plan.get("vm_id")
    snapshot_name = plan.get("snapshot_name", "pre-patch")

    if vm_id:
        try:
            clone_svc = CloneService()
            rollback_result = clone_svc.rollback_snapshot(vm_id=vm_id, snapshot_name=snapshot_name)
            if not rollback_result.success:
                logger.error("Snapshot rollback failed: %s", rollback_result.error)
        except Exception as exc:
            logger.exception("Snapshot rollback error: %s", exc)

    # Update counters based on retry type
    if status == "retry_next_strategy":
        new_strategy_idx = strategy_idx + 1
        new_attempt = 1
    else:  # retry_same_strategy
        new_strategy_idx = strategy_idx
        new_attempt = attempt + 1

    new_strategy = STRATEGY_LADDER[new_strategy_idx] if new_strategy_idx < len(STRATEGY_LADDER) else "unknown"
    logger.info("Replanning: strategy=%s, attempt=%d, total=%d", new_strategy, new_attempt, total + 1)

    return {
        "current_strategy_index": new_strategy_idx,
        "attempt_within_strategy": new_attempt,
        "total_attempts": total + 1,
        "strategy_history": history,
        "strategy": new_strategy,
        "execution_result": None,
        "verification_results": None,
        "status": "replanning",
    }
