"""Retry decision node — evaluates whether to retry, escalate, or dead-letter."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from src.agents.state import AutopatchState

logger = logging.getLogger(__name__)

STRATEGY_LADDER: list[str] = [
    "vendor_patch",
    "config_workaround",
    "compensating_control",
]

MAX_ATTEMPTS_PER_STRATEGY = 2
GLOBAL_TIMEOUT_MINUTES = 60


def _global_timeout_exceeded(state: AutopatchState) -> bool:
    started = state.get("remediation_started_at")
    if not started:
        return False
    start_time = datetime.fromisoformat(started)
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    return elapsed > GLOBAL_TIMEOUT_MINUTES * 60


def retry_decision_node(state: AutopatchState) -> dict:
    verification = state.get("verification_results", {})

    if verification.get("overall") == "crash":
        logger.warning("Clone crashed — sending to dead letter")
        return {
            "status": "dead_letter",
            "dead_letter_reason": "clone_crash",
        }

    if _global_timeout_exceeded(state):
        logger.warning("Global timeout exceeded — sending to dead letter")
        return {
            "status": "dead_letter",
            "dead_letter_reason": "timeout",
        }

    attempt = state.get("attempt_within_strategy", 1)
    strategy_idx = state.get("current_strategy_index", 0)

    if attempt < MAX_ATTEMPTS_PER_STRATEGY:
        logger.info("Retrying same strategy (attempt %d → %d)", attempt, attempt + 1)
        return {"status": "retry_same_strategy"}

    if strategy_idx < len(STRATEGY_LADDER) - 1:
        next_strategy = STRATEGY_LADDER[strategy_idx + 1]
        logger.info("Escalating from %s to %s", STRATEGY_LADDER[strategy_idx], next_strategy)
        return {"status": "retry_next_strategy"}

    logger.warning("All strategies exhausted — sending to dead letter")
    return {
        "status": "dead_letter",
        "dead_letter_reason": "all_strategies_exhausted",
    }
