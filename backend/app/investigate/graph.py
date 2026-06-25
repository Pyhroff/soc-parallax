"""Autonomous investigation pipeline.

A DETERMINISTIC LangGraph: collect -> baseline_compare -> mitre_map -> correlate
-> narrate. Each node is a pure function over InvestigationState. The per-node
output is captured in `state['steps']` so the UI can show the agent's reasoning
(a glass-box agent, not a black box).

Falls back to sequential execution if langgraph isn't installed, so the pipeline
is always runnable and testable.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, TypedDict

from app.db import postgres as pg
from app.detect.scorer import score_event
from app.graph import queries as gq
from app.narrate.narrator import narrate
from app.schemas.detection import Detection
from app.schemas.event import UnifiedEvent


class InvestigationState(TypedDict, total=False):
    entity_type: str
    entity_id: str
    window_hours: int
    events: list[dict]
    detections: list[Detection]
    techniques: list[dict]
    related: dict
    narrative: str
    steps: list[dict]


def _log(state: InvestigationState, node: str, summary: str) -> None:
    state.setdefault("steps", []).append({"node": node, "summary": summary})


# ---- nodes ----
def collect(state: InvestigationState) -> InvestigationState:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=state.get("window_hours", 24))
    col = '"user"' if state["entity_type"] == "user" else "host"
    rows = pg.query(
        f'SELECT payload FROM events WHERE {col}=%s AND "timestamp" >= %s ORDER BY "timestamp"',
        (state["entity_id"], cutoff),
    )
    state["events"] = [r["payload"] for r in rows]
    _log(state, "collect", f"Collected {len(rows)} events for {state['entity_type']} "
                           f"'{state['entity_id']}' over {state.get('window_hours',24)}h")
    return state


def baseline_compare(state: InvestigationState) -> InvestigationState:
    dets: list[Detection] = []
    for payload in state.get("events", []):
        ev = UnifiedEvent.model_validate(payload)
        det = score_event(ev)
        if det:
            dets.append(det)
    state["detections"] = dets
    _log(state, "baseline_compare",
         f"Scored events against baselines; {len(dets)} anomalous detection(s)")
    return state


def mitre_map(state: InvestigationState) -> InvestigationState:
    refs: dict[str, dict] = {}
    for d in state.get("detections", []):
        for ref in d.mitre:
            refs[ref.technique_id] = ref.model_dump()
    state["techniques"] = list(refs.values())
    _log(state, "mitre_map", f"Mapped {len(refs)} MITRE technique(s): "
                            f"{', '.join(sorted(refs.keys())) or 'none'}")
    return state


def correlate(state: InvestigationState) -> InvestigationState:
    related: dict[str, Any] = {}
    try:
        if state["entity_type"] == "user":
            related["blast_radius"] = gq.blast_radius(state["entity_id"])
        for t in state.get("techniques", []):
            nxt = gq.likely_next_techniques(t["technique_id"])
            if nxt:
                related.setdefault("predicted_next", []).extend(nxt)
    except Exception as exc:  # graph optional
        related["graph_error"] = str(exc)
    state["related"] = related
    _log(state, "correlate", f"Queried memory graph; "
                            f"{len(related.get('blast_radius', []))} related host(s)")
    return state


def narrate_node(state: InvestigationState) -> InvestigationState:
    dets = state.get("detections", [])
    if dets:
        top = max(dets, key=lambda d: d.score)
        text, ground = narrate(top)
        state["narrative"] = text
        _log(state, "narrate", f"Generated narrative (grounded={ground.ok})")
    else:
        state["narrative"] = "No anomalous activity detected for this entity in the window."
        _log(state, "narrate", "No detections — benign window")
    return state


# ---- graph assembly ----
def _build_compiled():
    from langgraph.graph import END, START, StateGraph

    g = StateGraph(InvestigationState)
    g.add_node("collect", collect)
    g.add_node("baseline_compare", baseline_compare)
    g.add_node("mitre_map", mitre_map)
    g.add_node("correlate", correlate)
    g.add_node("narrate", narrate_node)
    g.add_edge(START, "collect")
    g.add_edge("collect", "baseline_compare")
    g.add_edge("baseline_compare", "mitre_map")
    g.add_edge("mitre_map", "correlate")
    g.add_edge("correlate", "narrate")
    g.add_edge("narrate", END)
    return g.compile()


def run_investigation(entity_type: str, entity_id: str, window_hours: int = 24) -> dict:
    state: InvestigationState = {
        "entity_type": entity_type, "entity_id": entity_id, "window_hours": window_hours,
    }
    try:
        compiled = _build_compiled()
        final = compiled.invoke(state)
    except Exception:
        # sequential fallback — same nodes, no langgraph dependency
        for node in (collect, baseline_compare, mitre_map, correlate, narrate_node):
            state = node(state)
        final = state

    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "window_hours": window_hours,
        "steps": final.get("steps", []),
        "detection_count": len(final.get("detections", [])),
        "techniques": final.get("techniques", []),
        "related": final.get("related", {}),
        "narrative": final.get("narrative", ""),
        "detections": [d.model_dump(mode="json") for d in final.get("detections", [])],
    }
