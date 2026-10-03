from datetime import datetime, timedelta, timezone

import app.investigate.graph as inv
from app.correlate.incidents import order_techniques
from app.schemas.detection import MitreRef

T0 = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def ref(tid, tactic):
    return MitreRef(technique_id=tid, tactic=tactic, name=tid)


def test_precedes_order_follows_observed_time_not_textbook_kill_chain():
    # Lateral Movement observed BEFORE Execution; textbook rank would reverse them.
    obs = [(T0, [ref("T1021", "Lateral Movement")]),
           (T0 + timedelta(minutes=5), [ref("T1059", "Execution")])]
    assert [r.technique_id for r in order_techniques(obs)] == ["T1021", "T1059"]


def test_first_observation_wins_and_ties_use_tactic_rank():
    obs = [(T0 + timedelta(minutes=9), [ref("T1059", "Execution")]),
           (T0, [ref("T1059", "Execution"), ref("T1003", "Credential Access")])]
    assert [r.technique_id for r in order_techniques(obs)] == ["T1059", "T1003"]


def test_investigation_falls_back_only_when_langgraph_missing(monkeypatch):
    ran = []
    for name in ("collect", "baseline_compare", "mitre_map", "correlate", "narrate_node"):
        monkeypatch.setattr(inv, name, lambda s, n=name: (ran.append(n), s)[1])

    def missing():
        raise ImportError("no langgraph")
    monkeypatch.setattr(inv, "_build_compiled", missing)
    out = inv.run_investigation("host", "WS-07")
    assert ran == ["collect", "baseline_compare", "mitre_map", "correlate", "narrate_node"]
    assert out["entity_id"] == "WS-07"


def test_real_errors_are_not_swallowed(monkeypatch):
    class Broken:
        def invoke(self, _):
            raise RuntimeError("db exploded")
    monkeypatch.setattr(inv, "_build_compiled", lambda: Broken())
    try:
        inv.run_investigation("host", "WS-07")
    except RuntimeError:
        return
    raise AssertionError("RuntimeError was swallowed")
