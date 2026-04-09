"""LangGraph workflow definition for the Autopatch agent pipeline.

Flow:
  evaluator → research → docs → lead → executor → verification → route_verification
                                                                    ↓           ↓
                                                                (PASS)      (FAIL/CRASH)
                                                                    ↓           ↓
                                                                finalize   retry_decision → route_retry
                                                                    ↓                        ↓         ↓
                                                                   END              rollback_and_   dead_letter
                                                                                    replan → lead →     ↓
                                                                                    executor           END
"""

import logging
from datetime import datetime, timezone

from langgraph.graph import StateGraph, END

from src.agents.state import AutopatchState
from src.agents.evaluator_agent import evaluator_node
from src.agents.research_agent import research_node
from src.agents.docs_agent import docs_node
from src.agents.executor_agent import executor_node
from src.agents.verification_agent import verification_node
from src.agents.lead_agent import lead_node
from src.agents.nodes.retry_decision import retry_decision_node
from src.agents.nodes.rollback_and_replan import rollback_and_replan_node
from src.agents.nodes.dead_letter import dead_letter_node

logger = logging.getLogger(__name__)


def _finalize_node(state: AutopatchState) -> dict:
    if state.get("scope_decision") == "out_of_scope":
        return {"status": "out_of_scope"}
    if (state.get("verification_results") or {}).get("overall") == "pass":
        return {"status": "remediated"}
    if state.get("execution_result"):
        return {"status": "executed"}
    return {"status": "complete"}


def _init_retry_state(state: AutopatchState) -> dict:
    """Initialize retry tracking on first executor entry."""
    if not state.get("remediation_started_at"):
        return {"remediation_started_at": datetime.now(timezone.utc).isoformat()}
    return {}


def _route_after_evaluator(state: AutopatchState) -> str:
    if state["scope_decision"] == "out_of_scope":
        return "finalize"
    return "research"


def _route_after_docs(state: AutopatchState) -> str:
    """Route to lead agent if a remediation plan needs generating, or finalize."""
    plan = state.get("remediation_plan")
    if plan and plan.get("target_host"):
        return "executor"
    return "lead"


def _route_after_lead(state: AutopatchState) -> str:
    """Route to executor if lead agent produced a plan."""
    plan = state.get("remediation_plan")
    if plan and plan.get("target_host"):
        return "executor"
    return "finalize"


def _route_after_verification(state: AutopatchState) -> str:
    """Route based on verification results."""
    results = state.get("verification_results", {})
    overall = results.get("overall", "fail")

    if overall == "pass":
        return "finalize"
    return "retry_decision"


def _route_after_retry(state: AutopatchState) -> str:
    """Route based on retry decision."""
    status = state.get("status", "")
    if status in ("retry_same_strategy", "retry_next_strategy"):
        return "rollback_and_replan"
    return "dead_letter"


def build_graph():
    graph = StateGraph(AutopatchState)

    # Nodes
    graph.add_node("evaluator", evaluator_node)
    graph.add_node("research", research_node)
    graph.add_node("docs", docs_node)
    graph.add_node("lead", lead_node)
    graph.add_node("init_retry", _init_retry_state)
    graph.add_node("executor", executor_node)
    graph.add_node("verification", verification_node)
    graph.add_node("retry_decision", retry_decision_node)
    graph.add_node("rollback_and_replan", rollback_and_replan_node)
    graph.add_node("dead_letter", dead_letter_node)
    graph.add_node("finalize", _finalize_node)

    # Entry
    graph.set_entry_point("evaluator")

    # Edges
    graph.add_conditional_edges("evaluator", _route_after_evaluator, {
        "finalize": "finalize",
        "research": "research",
    })
    graph.add_edge("research", "docs")
    graph.add_conditional_edges("docs", _route_after_docs, {
        "executor": "init_retry",
        "lead": "lead",
    })
    graph.add_conditional_edges("lead", _route_after_lead, {
        "executor": "init_retry",
        "finalize": "finalize",
    })
    graph.add_edge("init_retry", "executor")
    graph.add_edge("executor", "verification")
    graph.add_conditional_edges("verification", _route_after_verification, {
        "finalize": "finalize",
        "retry_decision": "retry_decision",
    })
    graph.add_conditional_edges("retry_decision", _route_after_retry, {
        "rollback_and_replan": "rollback_and_replan",
        "dead_letter": "dead_letter",
    })
    graph.add_edge("rollback_and_replan", "lead")
    graph.add_edge("dead_letter", "finalize")
    graph.add_edge("finalize", END)

    return graph.compile()
