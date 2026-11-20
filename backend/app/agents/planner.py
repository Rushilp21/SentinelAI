from __future__ import annotations

from typing import Any, TypedDict


class PlanState(TypedDict, total=False):
    scenario: str
    plan: dict[str, Any]


SCENARIOS: dict[str, dict[str, Any]] = {
    "idor": {
        "endpoint": "GET /api/travel/bookings/{booking_id}",
        "category": "Broken access control",
        "reason": "The route accepts a booking identifier, and each booking is owned by one agency.",
        "principal": "agent@northstar.demo",
        "preconditions": ["Northstar agent session", "Known synthetic booking 202 belongs to Meridian"],
        "procedure": ["Read own booking 101 as a control", "Request foreign booking 202 with the same agent session"],
        "expected": "Own booking is readable; foreign booking returns 403 or 404.",
        "verification": "Compare both HTTP responses and check whether foreign booking data was returned.",
        "risk": "High",
        "workflow": "Search & Booking → Agency Authorization",
    },
    "fare": {
        "endpoint": "POST /api/travel/bookings",
        "category": "Business logic",
        "reason": "Booking creation writes a financial amount and consumes a client-supplied fare field.",
        "principal": "agent@northstar.demo",
        "preconditions": ["Flight 1 is priced at ₹12,000", "Synthetic test traveller"],
        "procedure": ["Submit the known flight with fare ₹1", "Read the persisted booking and synthetic payment ledger"],
        "expected": "The stored booking and payment use the server catalogue fare.",
        "verification": "Compare submitted fare, stored booking amount and server-defined flight price.",
        "risk": "High",
        "workflow": "Flight Search → Booking → Payment",
    },
    "refund": {
        "endpoint": "POST /api/travel/bookings/{booking_id}/refund",
        "category": "Business logic",
        "reason": "Refund requests create financial ledger entries and follow cancellation state.",
        "principal": "admin@northstar.demo",
        "preconditions": ["Fresh synthetic booking", "Booking cancelled through TravelCore"],
        "procedure": ["Submit one refund", "Repeat the same bounded refund request", "Count entries for that synthetic booking"],
        "expected": "The second refund is rejected and exactly one refund ledger entry exists.",
        "verification": "Count synthetic refund ledger entries and compare the second request status.",
        "risk": "Critical",
        "workflow": "Booking → Cancellation → Refund",
    },
}


def deterministic_plan(scenario: str) -> dict[str, Any]:
    if scenario not in SCENARIOS:
        raise ValueError("Unsupported local demo scenario")
    plan = dict(SCENARIOS[scenario])
    plan["scenario"] = scenario
    plan["approval_required"] = False
    return plan


def create_plan(scenario: str) -> dict[str, Any]:
    """Run the same constrained plan node through LangGraph when available.

    The graph only selects from fixed local scenario plans; it cannot create a
    target URL or supply arbitrary requests. When LangGraph is absent, use the
    identical deterministic function directly.
    """
    try:
        from langgraph.graph import END, StateGraph
    except ImportError:
        return deterministic_plan(scenario)

    def select_node(state: dict[str, Any]) -> dict[str, Any]:
        return {"plan": deterministic_plan(state["scenario"])}

    graph = StateGraph(PlanState)
    graph.add_node("select_bounded_plan", select_node)
    graph.set_entry_point("select_bounded_plan")
    graph.add_edge("select_bounded_plan", END)
    return graph.compile().invoke({"scenario": scenario})["plan"]
