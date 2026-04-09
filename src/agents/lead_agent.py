"""Lead agent — orchestrates remediation strategy planning via LLM."""

import json
import logging
from pathlib import Path

from src.agents.state import AutopatchState

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "lead.md"

_OS_PACKAGE_HINTS = {
    "ubuntu": "apt-get",
    "debian": "apt-get",
    "centos": "yum",
    "rhel": "yum",
    "fedora": "dnf",
    "rocky": "dnf",
    "alma": "dnf",
}


def _call_llm(messages: list[dict], model: str | None = None):
    """Call the LLM via OpenAI-compatible API."""
    from src.agents.llm import get_llm_client, get_model_name
    client = get_llm_client()
    return client.chat.completions.create(
        model=model or get_model_name(),
        messages=messages,
        temperature=0.2,
        max_tokens=3000,
    )


def _build_context(state: AutopatchState) -> str:
    """Build the user message with all gathered context for the lead agent."""
    scan = state["scan_data"]
    cve_details = state.get("cve_details") or {}
    doc_chunks = state.get("doc_chunks", [])

    os_family = scan.get("os_family", "unknown")
    pkg_manager = _OS_PACKAGE_HINTS.get(os_family, "apt-get")

    sections = [
        "## Vulnerability",
        f"- Title: {scan.get('title', 'Unknown')}",
        f"- CVE: {state.get('cve_id', 'N/A')}",
        f"- Severity: {scan.get('severity', 'unknown')} (CVSS: {state.get('cvss_score', 'N/A')})",
        f"- EPSS: {state.get('epss_score', 'N/A')}",
        f"- KEV: {state.get('is_kev', False)}",
        f"- SSVC Decision: {state.get('ssvc_decision', 'N/A')}",
        f"- Affected package: {scan.get('affected_package', 'unknown')}",
        f"- Affected version: {scan.get('affected_version', 'unknown')}",
        f"- Fixed version: {scan.get('fixed_version', cve_details.get('fixed_version', 'unknown'))}",
        "",
        "## Asset",
        f"- OS: {os_family}",
        f"- Package manager: {pkg_manager}",
        f"- Environment: {scan.get('environment', 'production')}",
        f"- Criticality: {state.get('asset_criticality', 'medium')}",
        "",
        "## Research Summary",
        f"{cve_details.get('summary', 'No research summary available.')}",
        f"- Fix available: {cve_details.get('fix_available', 'unknown')}",
        "",
    ]

    if doc_chunks:
        sections.append("## Documentation Guidance")
        for i, chunk in enumerate(doc_chunks, 1):
            sections.append(f"{i}. {chunk}")
        sections.append("")

    advisories = state.get("vendor_advisories", [])
    if advisories:
        sections.append("## Vendor Advisories")
        for url in advisories:
            sections.append(f"- {url}")

    # Retry context (for re-planning after failure)
    history = state.get("strategy_history", [])
    if history:
        sections.append("")
        sections.append("## Previous Attempts (FAILED — do NOT repeat)")
        for i, attempt in enumerate(history, 1):
            sections.append(f"### Attempt {i}: {attempt.get('strategy', 'unknown')}")
            sections.append(f"- Error: {attempt.get('error', 'unknown')}")
            cmds = attempt.get("commands", [])
            if cmds:
                sections.append(f"- Commands tried: {len(cmds)}")
                for cmd_entry in cmds[:3]:
                    if isinstance(cmd_entry, dict):
                        sections.append(f"  - `{cmd_entry.get('command', '')}` → exit {cmd_entry.get('exit_code', '?')}")
        sections.append("")
        forced_strategy = state.get("strategy")
        if forced_strategy:
            sections.append(f"**You MUST use strategy: {forced_strategy}**")
            sections.append("Plan a DIFFERENT approach than previous attempts.")

    return "\n".join(sections)


async def lead_node(state: AutopatchState) -> dict:
    """LangGraph node: plan remediation strategy based on research + docs."""
    system_prompt = _PROMPT_PATH.read_text()
    user_message = _build_context(state)

    try:
        completion = _call_llm([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ])
        response_text = completion.choices[0].message.content.strip()
        if response_text.startswith("```"):
            response_text = response_text.split("\n", 1)[1].rsplit("```", 1)[0]
        plan = json.loads(response_text)
    except json.JSONDecodeError as e:
        logger.error("Lead agent returned invalid JSON: %s", e)
        return {
            "remediation_plan": None,
            "strategy": None,
            "status": "error",
            "error": f"Lead agent returned invalid JSON: {e}",
        }
    except Exception as e:
        logger.error("Lead agent LLM call failed: %s", e)
        return {
            "remediation_plan": None,
            "strategy": None,
            "status": "error",
            "error": f"LLM call failed: {e}",
        }

    strategy = plan.get("strategy", "unknown")

    return {
        "remediation_plan": plan,
        "strategy": strategy,
        "status": "complete",
    }
