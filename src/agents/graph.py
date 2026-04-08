"""LangGraph workflow — evaluator → research → docs → lead agent."""

from langgraph.graph import StateGraph, END

from src.agents.state import AutopatchState
from src.agents.evaluator_agent import evaluator_node
from src.agents.research_agent import research_node
from src.agents.docs_agent import docs_node
from src.agents.lead_agent import lead_node


def _route_after_evaluator(state: AutopatchState) -> str:
    """Conditional edge: route based on scope decision."""
    if state.get("scope_decision") == "in_scope":
        return "research"
    return END


def build_graph():
    """Build and compile the Autopatch LangGraph workflow.

    Flow:
        START → evaluator → (in_scope?) → research → docs → lead → END
                                  ↘ (out_of_scope) → END
    """
    graph = StateGraph(AutopatchState)

    graph.add_node("evaluator", evaluator_node)
    graph.add_node("research", research_node)
    graph.add_node("docs", docs_node)
    graph.add_node("lead", lead_node)

    graph.set_entry_point("evaluator")

    graph.add_conditional_edges(
        "evaluator",
        _route_after_evaluator,
        {"research": "research", END: END},
    )

    graph.add_edge("research", "docs")
    graph.add_edge("docs", "lead")
    graph.add_edge("lead", END)

    return graph.compile()
