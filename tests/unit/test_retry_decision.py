"""Unit tests for the retry decision node."""

import pytest
from datetime import datetime, timedelta, timezone

from src.agents.nodes.retry_decision import retry_decision_node, STRATEGY_LADDER


class TestRetryDecision:
    def _make_state(self, **overrides):
        base = {
            "verification_results": {"overall": "fail", "failure_reason": "Nuclei still detects vuln"},
            "current_strategy_index": 0,
            "attempt_within_strategy": 1,
            "total_attempts": 1,
            "remediation_started_at": datetime.now(timezone.utc).isoformat(),
            "strategy_history": [],
        }
        base.update(overrides)
        return base

    def test_first_failure_retries_same_strategy(self):
        state = self._make_state(attempt_within_strategy=1)
        result = retry_decision_node(state)
        assert result["status"] == "retry_same_strategy"

    def test_second_failure_escalates_to_next_strategy(self):
        state = self._make_state(attempt_within_strategy=2, current_strategy_index=0)
        result = retry_decision_node(state)
        assert result["status"] == "retry_next_strategy"

    def test_all_strategies_exhausted_goes_to_dead_letter(self):
        state = self._make_state(
            attempt_within_strategy=2,
            current_strategy_index=2,
        )
        result = retry_decision_node(state)
        assert result["status"] == "dead_letter"
        assert result["dead_letter_reason"] == "all_strategies_exhausted"

    def test_crash_goes_to_dead_letter_immediately(self):
        state = self._make_state(
            verification_results={"overall": "crash", "failure_reason": "unreachable"},
        )
        result = retry_decision_node(state)
        assert result["status"] == "dead_letter"
        assert result["dead_letter_reason"] == "clone_crash"

    def test_timeout_goes_to_dead_letter(self):
        old_time = (datetime.now(timezone.utc) - timedelta(minutes=90)).isoformat()
        state = self._make_state(remediation_started_at=old_time)
        result = retry_decision_node(state)
        assert result["status"] == "dead_letter"
        assert result["dead_letter_reason"] == "timeout"

    def test_strategy_ladder_has_three_entries(self):
        assert len(STRATEGY_LADDER) == 3
        assert STRATEGY_LADDER[0] == "vendor_patch"
        assert STRATEGY_LADDER[1] == "config_workaround"
        assert STRATEGY_LADDER[2] == "compensating_control"
