"""Docs agent — fetches advisory URLs, extracts remediation guidance via LLM."""

import json
import logging
from pathlib import Path

from src.agents.state import AutopatchState
from src.agents.tools.docs_tool import fetch_url

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "docs.md"
_MAX_URLS = 3


def _call_llm(messages: list[dict], model: str | None = None):
    """Call the LLM via OpenAI-compatible API."""
    from src.agents.llm import get_llm_client, get_model_name
    client = get_llm_client()
    return client.chat.completions.create(
        model=model or get_model_name(),
        messages=messages,
        temperature=0.1,
        max_tokens=2000,
    )


async def docs_node(state: AutopatchState) -> dict:
    """LangGraph node: fetch advisory URLs and extract remediation steps."""
    # Collect unique URLs from vendor_advisories + references
    urls: list[str] = []
    seen: set[str] = set()
    for url in state.get("vendor_advisories", []) + state.get("references", []):
        if url not in seen:
            seen.add(url)
            urls.append(url)
    urls = urls[:_MAX_URLS]

    if not urls:
        return {
            "doc_chunks": [],
            "doc_sources": [],
            "status": "researching",
        }

    # Fetch all URLs
    fetched: list[tuple[str, str]] = []
    for url in urls:
        content = await fetch_url(url)
        if content is not None:
            fetched.append((url, content))

    if not fetched:
        return {
            "doc_chunks": [],
            "doc_sources": urls,
            "status": "researching",
        }

    # Build LLM prompt with fetched content
    system_prompt = _PROMPT_PATH.read_text()
    doc_sections = []
    for url, content in fetched:
        truncated = content[:10_000]
        doc_sections.append(f"--- Source: {url} ---\n{truncated}")

    user_message = (
        f"Vulnerability: {state['scan_data'].get('title', 'Unknown')}\n"
        f"CVE: {state.get('cve_id', 'N/A')}\n"
        f"Affected package: {state['scan_data'].get('affected_package', 'unknown')}\n\n"
        f"Fetched documentation:\n\n" + "\n\n".join(doc_sections)
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

        doc_chunks = parsed.get("remediation_steps", [])
        doc_sources = parsed.get("sources", [u for u, _ in fetched])
    except Exception as e:
        logger.warning("Docs LLM call failed: %s", e)
        # Fall back to raw fetched text as chunks
        doc_chunks = [content[:5000] for _, content in fetched]
        doc_sources = [url for url, _ in fetched]

    return {
        "doc_chunks": doc_chunks,
        "doc_sources": doc_sources,
        "status": "researching",
    }
