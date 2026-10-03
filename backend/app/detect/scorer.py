"""The scorer — combines rarity signals (vs baseline) and contextual rules into
an attributable Detection. Every point of the final score traces to a signal.

Calibration rules (each exists because the opposite was measured to be wrong):
  * Rarity needs history. A baseline with fewer than `min_baseline_samples`
    observations (or none) yields NO rarity signal, so an unseen user/host is
    not flagged just for being new.
  * A feature is counted once per event even when both the user and the host
    baseline observe it (taking the stronger of the two), instead of twice.
  * Without a contextual rule behind it, a baseline anomaly is capped at
    `rarity_only_cap` (medium). High/critical require rule evidence.
  * Rarity signals carry no MITRE technique: "unusual" is not "T1059.001".
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


def _has_history(baseline: dict | None) -> bool:
    return bool(baseline) and baseline["sample_count"] >= settings.min_baseline_samples


def rarity_signals(ev: UnifiedEvent, baseline_fn) -> list[Signal]:
    """At most one rarity signal per feature, only where there is enough history."""
    best: dict[str, Signal] = {}
    for o in extract(ev):
        weight = RARITY_WEIGHTS.get(o.feature)
        if weight is None:
            continue
        baseline = baseline_fn(o.entity_type, o.entity_id, o.feature)
        if not _has_history(baseline):
            continue                                    # cold start: no signal, not a max-surprise signal
        sub = rarity_score(baseline, o.value)
        if sub < RARITY_MIN:
            continue
        seen = baseline["distribution"].get(o.value, 0)
        sig = Signal(
            name=f"rarity:{o.feature}", weight=weight, sub_score=round(sub, 3),
            contribution=round(weight * sub * 100, 2),
            evidence=(f"{o.feature}='{o.value}' is rare for {o.entity_type} '{o.entity_id}' "
                      f"(seen {seen} of {baseline['sample_count']} observations)"),
            mitre=[],
        )
        if o.feature not in best or sig.contribution > best[o.feature].contribution:
            best[o.feature] = sig
    return list(best.values())


def score_event(ev: UnifiedEvent, baseline_fn=None) -> Detection | None:
    """Score one event. `baseline_fn(entity_type, entity_id, feature)->dict|None`
    is injectable so batch jobs and the metrics harness can use in-memory baselines.
    Resolved at call time so tests can monkeypatch `get_baseline`."""
    if baseline_fn is None:
        baseline_fn = get_baseline
    signals: list[Signal] = rarity_signals(ev, baseline_fn)

    rule_hits = rules.evaluate(ev)
    for hit in rule_hits:
        signals.append(Signal(
            name=hit.name, weight=RULE_WEIGHT, sub_score=round(hit.sub_score, 3),
            contribution=round(RULE_WEIGHT * hit.sub_score * 100, 2),
            evidence=hit.evidence, mitre=mitre.techniques_for(hit.name),
        ))

    if not signals:
        return None

    score = min(100.0, sum(s.contribution for s in signals))
    if not rule_hits:
        score = min(score, settings.rarity_only_cap)
    score = round(score, 2)
    entity_type, entity_id = _primary_entity(ev)

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


_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_BATCH = 2000


def _preload_baselines():
    """Load every baseline once; scoring then needs no per-event queries."""
    rows = pg.query("SELECT entity_type, entity_id, feature, distribution, sample_count FROM baselines")
    store = {(r["entity_type"], r["entity_id"], r["feature"]):
             {"distribution": r["distribution"], "sample_count": r["sample_count"]} for r in rows}
    return lambda t, e, f: store.get((t, e, f))


def run_detection_over_events(min_severity: str = "low") -> dict:
    """Score every stored event without a detection, in batches (bounded memory,
    one baseline load, one batched insert per batch)."""
    floor = _ORDER[min_severity]
    baseline_fn = _preload_baselines()
    evaluated = created = 0
    after = "00000000-0000-0000-0000-000000000000"
    while True:
        rows = pg.query(
            """
            SELECT e.event_id, e.payload FROM events e
            LEFT JOIN detections d ON d.event_id = e.event_id
            WHERE d.detection_id IS NULL AND e.event_id > %s::uuid
            ORDER BY e.event_id LIMIT %s
            """,
            (after, _BATCH),
        )
        if not rows:
            break
        after = str(rows[-1]["event_id"])
        batch = []
        for row in rows:
            det = score_event(UnifiedEvent.model_validate(row["payload"]), baseline_fn)
            if det and _ORDER[det.severity] >= floor:
                batch.append((
                    str(det.event_id), det.entity_type, det.entity_id, det.score, det.severity,
                    pg.as_jsonb([s.model_dump() for s in det.signals]),
                    pg.as_jsonb([m.model_dump() for m in det.mitre]),
                ))
        evaluated += len(rows)
        if batch:
            with pg.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.executemany(
                        "INSERT INTO detections (event_id, entity_type, entity_id, score, severity, signals, mitre) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s)", batch)
                conn.commit()
            created += len(batch)
    return {"events_evaluated": evaluated, "detections_created": created}
