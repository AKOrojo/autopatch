"""LangGraph workflow definition for the Autopatch agent pipeline."""
import logging
from langgraph.graph import StateGraph, END
from src.agents.state import AutopatchState
from src.agents.evaluator_agent import evaluator_node
from src.agents.research_agent import research_node
from src.agents.docs_agent import docs_node

logger = logging.getLogger(__name__)

def _finalize_node(state: AutopatchState) -> dict:
    if state.get("scope_decision") == "out_of_scope":
        return {"status": "out_of_scope"}
    return {"status": "complete"}

def _route_after_evaluator(state: AutopatchState) -> str:
    if state["scope_decision"] == "out_of_scope":
        return "finalize"
    return "research"

def build_graph():
    graph = StateGraph(AutopatchState)
    graph.add_node("evaluator", evaluator_node)
    graph.add_node("research", research_node)
    graph.add_node("docs", docs_node)
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
