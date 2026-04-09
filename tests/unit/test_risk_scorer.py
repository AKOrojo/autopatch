# tests/unit/test_risk_scorer.py
"""Unit tests for the LLM risk scorer."""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock

from src.agents.sandbox.risk_scorer import RiskScorer, RiskVerdict


@pytest.fixture
def scorer():
    return RiskScorer()


class TestRiskVerdict:
    def test_low_risk_auto_approved(self):
        v = RiskVerdict(score=2, reasoning="Safe read command", category="info_gathering")
        assert v.approved
        assert v.audit_level == "info"

    def test_medium_risk_approved_with_warning(self):
        v = RiskVerdict(score=5, reasoning="Unusual but not dangerous", category="config_change")
        assert v.approved
        assert v.audit_level == "warning"

    def test_high_risk_blocked(self):
        v = RiskVerdict(score=8, reasoning="Potentially destructive", category="system_modification")
        assert not v.approved
        assert v.audit_level == "critical"

    def test_boundary_score_6_approved(self):
        v = RiskVerdict(score=6, reasoning="Borderline", category="unknown")
        assert v.approved

    def test_boundary_score_7_blocked(self):
        v = RiskVerdict(score=7, reasoning="Risky", category="unknown")
        assert not v.approved


class TestRiskScorerWithMockedLLM:
    @pytest.mark.asyncio
    async def test_low_risk_command(self, scorer):
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"score": 2, "reasoning": "Read-only info", "category": "info_gathering"}'

        with patch.object(scorer, "_call_llm", return_value=mock_response):
            verdict = await scorer.score("find /etc/ssh -name '*.conf'", context={})
            assert verdict.approved
            assert verdict.score == 2

    @pytest.mark.asyncio
    async def test_high_risk_command(self, scorer):
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"score": 9, "reasoning": "Could delete data", "category": "destructive"}'

        with patch.object(scorer, "_call_llm", return_value=mock_response):
            verdict = await scorer.score("shred /var/lib/mysql/data", context={})
            assert not verdict.approved
            assert verdict.score == 9

    @pytest.mark.asyncio
    async def test_timeout_blocks_command(self, scorer):
        """If LLM times out, fail-closed (block)."""
        with patch.object(scorer, "_call_llm", side_effect=TimeoutError("LLM timeout")):
            verdict = await scorer.score("unknown-binary --flag", context={})
            assert not verdict.approved
            assert verdict.score == 10
            assert "timeout" in verdict.reasoning.lower()

    @pytest.mark.asyncio
    async def test_invalid_json_blocks_command(self, scorer):
        """If LLM returns invalid JSON, fail-closed."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "I think this is fine"

        with patch.object(scorer, "_call_llm", return_value=mock_response):
            verdict = await scorer.score("unknown-binary", context={})
            assert not verdict.approved
            assert verdict.score == 10
