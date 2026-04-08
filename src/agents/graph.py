"""LangGraph workflow definition for the Autopatch agent pipeline."""
import logging
from langgraph.graph import StateGraph, END
from src.agents.state import AutopatchState
from src.agents.evaluator_agent import evaluator_node

logger = logging.getLogger(__name__)

def _research_node(state: AutopatchState) -> dict:
    """Placeholder for research agent — replaced in Task 13."""
    logger.info("Research node: stub (no-op)")
    return {"status": "researching"}

def _docs_node(state: AutopatchState) -> dict:
    """Placeholder for docs agent — replaced in Task 13."""
    logger.info("Docs node: stub (no-op)")
    return {}

def _finalize_node(state: AutopatchState) -> dict:
    return {"status": "complete"}

def _route_after_evaluator(state: AutopatchState) -> str:
    if state["scope_decision"] == "out_of_scope":
        return "finalize"
    return "research"

def build_graph():
    graph = StateGraph(AutopatchState)
    graph.add_node("evaluator", evaluator_node)
    graph.add_node("research", _research_node)
    graph.add_node("docs", _docs_node)
    graph.add_node("finalize", _finalize_node)
    graph.set_entry_point("evaluator")
    graph.add_conditional_edges("evaluator", _route_after_evaluator, {
        "finalize": "finalize",
        "research": "research",
    })
    graph.add_edge("research", "docs")
    graph.add_edge("docs", "finalize")
    graph.add_edge("finalize", END)
    return graph.compile()
