"""The scorer — combines rarity signals (vs baseline) and contextual rules into
an attributable Detection. Every point of the final score traces to a signal.
"""
from __future__ import annotations

from app.baseline.engine import get_baseline, rarity_score
from app.baseline.features import extract
from app.config import settings
from app.db import postgres as pg
from app.detect import mitre
from app.detect.signals import rules
from app.schemas.detection import Detection, Signal
from app.schemas.event import UnifiedEvent

# Per-feature rarity weights (importance of each behavioral dimension).
RARITY_WEIGHTS: dict[str, float] = {
    "process_name": 0.35,
    "parent_child": 0.30,
    "login_hour": 0.20,
    "src_ip": 0.20,
    "dest_ip": 0.20,
    "domain": 0.15,
}
RULE_WEIGHT = 0.50          # contextual rules are high-fidelity
RARITY_MIN = 0.55           # ignore rarity below this (not anomalous enough)


def _severity(score: float) -> str:
    if score >= settings.severity_critical:
        return "critical"
    if score >= settings.severity_medium:
        return "high"
    if score >= settings.severity_low:
        return "medium"
    return "low"


def _primary_entity(ev: UnifiedEvent) -> tuple[str, str]:
    if ev.user:
        return "user", ev.user
    if ev.host:
        return "host", ev.host
    if ev.process.name:
        return "process", ev.process.name.lower()
    return "unknown", "unknown"


def score_event(ev: UnifiedEvent, baseline_fn=None) -> Detection | None:
    """Score one event. `baseline_fn(entity_type, entity_id, feature)->dict|None`
    is injectable so the metrics harness can run with in-memory baselines.
    Resolved at call time so tests can monkeypatch `get_baseline`."""
    if baseline_fn is None:
        baseline_fn = get_baseline
    signals: list[Signal] = []

    # ---- rarity signals (need a baseline) ----
    for o in extract(ev):
        weight = RARITY_WEIGHTS.get(o.feature)
        if weight is None:
            continue
        baseline = baseline_fn(o.entity_type, o.entity_id, o.feature)
        sub = rarity_score(baseline, o.value)
        if sub < RARITY_MIN:
            continue
        name = f"rarity:{o.feature}"
        seen = (baseline["distribution"].get(o.value, 0) if baseline else 0)
        total = baseline["sample_count"] if baseline else 0
        evidence = (
            f"{o.feature}='{o.value}' is rare for {o.entity_type} '{o.entity_id}' "
            f"(seen {seen} of {total} observations)"
            if baseline else
            f"{o.feature}='{o.value}' — no behavioral history for {o.entity_type} '{o.entity_id}'"
        )
        signals.append(Signal(
            name=name, weight=weight, sub_score=round(sub, 3),
            contribution=round(weight * sub * 100, 2),
            evidence=evidence, mitre=mitre.techniques_for(name),
        ))

    # ---- contextual rule signals (no baseline needed) ----
    for hit in rules.evaluate(ev):
        signals.append(Signal(
            name=hit.name, weight=RULE_WEIGHT, sub_score=round(hit.sub_score, 3),
            contribution=round(RULE_WEIGHT * hit.sub_score * 100, 2),
            evidence=hit.evidence, mitre=mitre.techniques_for(hit.name),
        ))

    if not signals:
        return None

    score = round(min(100.0, sum(s.contribution for s in signals)), 2)
    entity_type, entity_id = _primary_entity(ev)

    # de-dupe MITRE refs across signals
    seen_t: dict[str, object] = {}
    for s in signals:
        for ref in s.mitre:
            seen_t[ref.technique_id] = ref

    return Detection(
        event_id=ev.event_id,
        entity_type=entity_type,
        entity_id=entity_id,
        score=score,
        severity=_severity(score),
        signals=sorted(signals, key=lambda s: s.contribution, reverse=True),
        mitre=list(seen_t.values()),
    )


def persist_detection(det: Detection) -> str:
    rows = pg.query(
        """
        INSERT INTO detections
            (event_id, entity_type, entity_id, score, severity, signals, mitre)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING detection_id
        """,
        (
            str(det.event_id), det.entity_type, det.entity_id, det.score, det.severity,
            pg.as_jsonb([s.model_dump() for s in det.signals]),
            pg.as_jsonb([m.model_dump() for m in det.mitre]),
        ),
    )
    return str(rows[0]["detection_id"])


def run_detection_over_events(min_severity: str = "low") -> dict:
    """Score every stored event that doesn't yet have a detection."""
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    rows = pg.query(
        """
        SELECT e.payload FROM events e
        LEFT JOIN detections d ON d.event_id = e.event_id
        WHERE d.detection_id IS NULL
        """
    )
    created = 0
    for row in rows:
        ev = UnifiedEvent.model_validate(row["payload"])
        det = score_event(ev)
        if det and order[det.severity] >= order[min_severity]:
            persist_detection(det)
            created += 1
    return {"events_evaluated": len(rows), "detections_created": created}
