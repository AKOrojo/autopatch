# src/agents/sandbox/sandbox_facade.py
"""Three-layer sandbox pipeline: argument_validator → allowlist → risk_scorer.

This module orchestrates the three security layers and is the single entry
point for command validation in the executor agent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from src.agents.sandbox.argument_validator import ArgumentValidator
from src.agents.sandbox.risk_scorer import RiskScorer, RiskVerdict
from src.agents.tools.command_sandbox import CommandSandbox

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SandboxResult:
    """Final result of the 3-layer sandbox pipeline."""

    allowed: bool
    command: str
    source: str  # "argument_validator" | "allowlist" | "risk_scorer"
    reason: str = ""
    risk_verdict: RiskVerdict | None = None


class SandboxFacade:
    """Orchestrates the 3-layer command sandbox pipeline.

    Flow:
      1. ArgumentValidator — blocks injection, dangerous patterns, bad paths
      2. CommandSandbox (allowlist) — auto-approves known-safe commands
      3. RiskScorer (LLM) — evaluates unknown commands that passed layers 1-2
    """

    def __init__(self) -> None:
        self._validator = ArgumentValidator()
        self._allowlist = CommandSandbox()
        self._risk_scorer = RiskScorer()

    async def evaluate(self, command: str, context: dict) -> SandboxResult:
        """Evaluate a command through all three layers."""

        # Layer 1: Argument validation (injection, dangerous patterns, paths)
        validation = self._validator.validate(command)
        if not validation.valid:
            logger.warning("Argument validator rejected: %s — %s", command, validation.rejection_reason)
            return SandboxResult(
                allowed=False,
                command=command,
                source="argument_validator",
                reason=validation.rejection_reason or "Validation failed",
            )

        # Layer 2: Allowlist check
        verdict = self._allowlist.validate(command)
        if verdict.allowed:
            return SandboxResult(
                allowed=True,
                command=command,
                source="allowlist",
                reason="Command in allowlist",
            )

        # If rejected because binary not in allowlist, proceed to risk scorer.
        # If rejected for other reasons (bad flags, bad args), still block.
        if "not in the allowlist" not in verdict.reason:
            logger.warning("Allowlist rejected (non-binary reason): %s — %s", command, verdict.reason)
            return SandboxResult(
                allowed=False,
                command=command,
                source="allowlist",
                reason=verdict.reason,
            )

        # Layer 3: LLM risk scoring for unknown commands
        logger.info("Command not in allowlist, scoring via LLM: %s", command)
        risk = await self._risk_scorer.score(command, context)

        if risk.approved:
            logger.info("Risk scorer approved (score=%d): %s", risk.score, command)
        else:
            logger.warning("Risk scorer blocked (score=%d): %s — %s", risk.score, command, risk.reasoning)

        return SandboxResult(
            allowed=risk.approved,
            command=command,
            source="risk_scorer",
            reason=risk.reasoning,
            risk_verdict=risk,
        )
