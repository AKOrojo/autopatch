"""Tests requiring a running vLLM instance. Run with: pytest -m live_llm"""
import os
import pytest
from dotenv import dotenv_values

# Load .env and force-set LLM vars (override unit-test defaults)
_env = dotenv_values(".env")
for key in ("LLM_BASE_URL", "LLM_MODEL"):
    if key in _env:
        os.environ[key] = _env[key]

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://autopatch:autopatch_dev@localhost:5432/autopatch")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("API_KEYS", "key1")

from src.agents.llm import get_llm_client, get_model_name, reset_client

@pytest.mark.live_llm
def test_vllm_health():
    reset_client()
    client = get_llm_client()
    models = client.models.list()
    assert len(models.data) > 0

@pytest.mark.live_llm
def test_vllm_completion():
    reset_client()
    client = get_llm_client()
    response = client.chat.completions.create(
        model=get_model_name(),
        messages=[{"role": "user", "content": "What is CVE-2021-44228? Answer in one sentence."}],
        max_tokens=100, temperature=0.1,
    )
    assert len(response.choices) == 1
    assert len(response.choices[0].message.content) > 10

@pytest.mark.live_llm
@pytest.mark.asyncio
async def test_full_graph_live():
    from src.agents.state import make_initial_state
    from src.agents.graph import build_graph
    state = make_initial_state("v1", "a1", "CVE-2021-44228", {
        "severity": "critical", "title": "Apache Log4j2 Remote Code Execution",
        "cvss_score": 10.0, "epss_score": 0.97, "is_kev": True,
        "asset_criticality": "critical",
    })
    graph = build_graph()
    result = await graph.ainvoke(state)
    assert result["scope_decision"] == "in_scope"
    assert result["ssvc_decision"] == "act"
    assert result["status"] == "complete"
