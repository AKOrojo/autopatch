"""LLM-based risk scoring for commands not in the allowlist.

This is the third and final layer of the sandbox pipeline. It is only
invoked for commands that (a) pass argument validation and (b) are NOT
in the command allowlist. The LLM evaluates risk on a 1-10 scale.

Fail-closed: any error (timeout, bad JSON, LLM down) → block the command.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

RISK_SCORER_SYSTEM_PROMPT = """\
You are a security risk scorer for a vulnerability remediation system.

You will be given a shell command that an AI agent wants to execute on a
remote Linux server to fix a vulnerability. The command was NOT in the
pre-approved allowlist, so you must evaluate its risk.

Score the command on a scale of 1-10:
- 1-3: Low risk. Read-only, informational, or standard admin commands.
- 4-6: Medium risk. Modifies config or state but in a controlled way.
- 7-10: High risk. Could cause data loss, service disruption, or security issues.

Respond ONLY with a JSON object (no markdown, no explanation outside JSON):
{"score": <int 1-10>, "reasoning": "<one sentence>", "category": "<category>"}

Categories: info_gathering, config_change, package_management, service_management,
network_change, file_modification, system_modification, destructive, unknown
"""

RISK_SCORER_USER_TEMPLATE = """\
Command: {command}

Context:
- Vulnerability: {vuln_id} ({cve_id})
- Strategy: {strategy}
- Asset OS: {os_family}
- Purpose: {purpose}

Is this command safe to execute?
"""

LLM_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class RiskVerdict:
    """Result of LLM risk scoring."""

    score: int
    reasoning: str
    category: str

    @property
    def approved(self) -> bool:
        return self.score <= 6

    @property
    def audit_level(self) -> str:
        if self.score <= 3:
            return "info"
        if self.score <= 6:
            return "warning"
        return "critical"


class RiskScorer:
    """Scores unknown commands via LLM for risk assessment."""

    def __init__(self, timeout: int = LLM_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout

    def _call_llm(self, messages: list[dict]):
        """Call LLM via OpenAI-compatible API."""
        from src.agents.llm import get_llm_client, get_model_name
        client = get_llm_client()
        return client.chat.completions.create(
            model=get_model_name(),
            messages=messages,
            temperature=0.1,
            max_tokens=200,
        )

    async def score(self, command: str, context: dict) -> RiskVerdict:
        """Score a command's risk level via LLM. Fail-closed on any error."""
        user_message = RISK_SCORER_USER_TEMPLATE.format(
            command=command,
            vuln_id=context.get("vulnerability_id", "unknown"),
            cve_id=context.get("cve_id", "N/A"),
            strategy=context.get("strategy", "unknown"),
            os_family=context.get("os_family", "unknown"),
            purpose=context.get("purpose", "remediation"),
        )

        messages = [
            {"role": "system", "content": RISK_SCORER_SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ]

        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(self._call_llm, messages),
                timeout=self._timeout,
            )
            raw = response.choices[0].message.content.strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
            parsed = json.loads(raw)

            score = int(parsed["score"])
            score = max(1, min(10, score))

            return RiskVerdict(
                score=score,
                reasoning=parsed.get("reasoning", ""),
                category=parsed.get("category", "unknown"),
            )

        except TimeoutError:
            logger.warning("Risk scorer LLM timed out for command: %s", command)
            return RiskVerdict(
                score=10,
                reasoning="LLM timeout — fail-closed",
                category="unknown",
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning("Risk scorer got invalid LLM response: %s", e)
            return RiskVerdict(
                score=10,
                reasoning=f"Invalid LLM response — fail-closed: {e}",
                category="unknown",
            )
        except Exception as e:
            logger.exception("Risk scorer unexpected error: %s", e)
            return RiskVerdict(
                score=10,
                reasoning=f"Unexpected error — fail-closed: {e}",
                category="unknown",
            )
