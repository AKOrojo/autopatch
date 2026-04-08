"""Research agent — LLM-powered CVE research with NVD lookup."""

import json
import logging
from pathlib import Path

from src.agents.state import AutopatchState
from src.agents.tools.nvd_tool import nvd_lookup

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "research.md"


def _get_enrichment_data(cve_id: str) -> dict | None:
    """Fetch enrichment data from DB using a sync session (for Celery workers)."""
    import os
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    db_url = os.environ.get("DATABASE_URL", "")
    sync_url = db_url.replace("+asyncpg", "+psycopg2")

    try:
        engine = create_engine(sync_url)
        with Session(engine) as session:
            return nvd_lookup(cve_id, session)
    except Exception as e:
        logger.warning("Failed to fetch enrichment for %s: %s", cve_id, e)
        return None


def _call_llm(messages: list[dict], model: str | None = None):
    """Call the LLM via OpenAI-compatible API."""
    from src.agents.llm import get_llm_client, get_model_name
    client = get_llm_client()
    return client.chat.completions.create(
        model=model or get_model_name(),
        messages=messages,
        temperature=0.2,
        max_tokens=2000,
    )


async def research_node(state: AutopatchState) -> dict:
    """LangGraph node: research the vulnerability using NVD data + LLM synthesis."""
    cve_id = state.get("cve_id")

    if not cve_id:
        return {
            "cve_details": None,
            "vendor_advisories": [],
            "references": [],
            "status": "researching",
        }

    # Step 1: NVD lookup
    nvd_result = _get_enrichment_data(cve_id)

    # Step 2: LLM synthesis
    system_prompt = _PROMPT_PATH.read_text()
    scan_data = state["scan_data"]
    user_message = (
        f"Vulnerability: {scan_data.get('title', 'Unknown')}\n"
        f"CVE: {cve_id}\n"
        f"Severity: {scan_data.get('severity', 'unknown')}\n"
        f"Affected package: {scan_data.get('affected_package', 'unknown')}\n"
        f"Affected version: {scan_data.get('affected_version', 'unknown')}\n"
        f"\nNVD data:\n{json.dumps(nvd_result, indent=2, default=str)}"
    )

    try:
        completion = _call_llm([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ])
        response_text = completion.choices[0].message.content.strip()
        if response_text.startswith("```"):
            response_text = response_text.split("\n", 1)[1].rsplit("```", 1)[0]
        parsed = json.loads(response_text)
    except Exception as e:
        logger.warning("Research LLM call failed for %s: %s", cve_id, e)
        # Fall back to NVD data only
        refs = []
        if nvd_result and nvd_result.get("references"):
            for ref in nvd_result["references"]:
                if isinstance(ref, dict):
                    refs.append(ref.get("url", ""))
                elif isinstance(ref, str):
                    refs.append(ref)
        parsed = {
            "summary": (nvd_result or {}).get("description", "LLM unavailable — using NVD data only."),
            "vendor_advisories": [],
            "fix_available": None,
            "fixed_version": None,
            "references": refs,
        }

    cve_details = {
        "cve_id": cve_id,
        "summary": parsed.get("summary", ""),
        "fix_available": parsed.get("fix_available"),
        "fixed_version": parsed.get("fixed_version"),
    }
    if nvd_result:
        cve_details["description"] = nvd_result.get("description")
        cve_details["cvss_v3_score"] = nvd_result.get("cvss_v3_score")
        cve_details["cvss_v3_vector"] = nvd_result.get("cvss_v3_vector")

    return {
        "cve_details": cve_details,
        "vendor_advisories": parsed.get("vendor_advisories", []),
        "references": parsed.get("references", []),
        "status": "researching",
    }
