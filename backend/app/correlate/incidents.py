"""Correlate detections into incidents.

Detections for the same entity within a time window are grouped into one
incident. The incident's MITRE techniques are ordered by ATT&CK kill-chain
tactic so the PRECEDES chain and narrative read in attack order.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from app.config import settings
from app.db import postgres as pg
from app.graph import writer
from app.narrate.narrator import narrate
from app.schemas.detection import Detection, MitreRef, Signal

# ATT&CK tactic kill-chain order (lower = earlier)
TACTIC_RANK = {
    "Initial Access": 0, "Execution": 1, "Persistence": 2, "Privilege Escalation": 3,
    "Defense Evasion": 4, "Credential Access": 5, "Discovery": 6, "Lateral Movement": 7,
    "Collection": 8, "Command and Control": 9, "Exfiltration": 10, "Impact": 11,
}
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _load_unassigned_detections() -> list[dict]:
    return pg.query(
        """
        SELECT d.detection_id, d.event_id, d.entity_type, d.entity_id, d.score,
               d.severity, d.signals, d.mitre, e."timestamp"
        FROM detections d
        JOIN events e ON e.event_id = d.event_id
        WHERE d.detection_id NOT IN (
            SELECT unnest(detection_ids) FROM incidents
        )
        ORDER BY d.entity_id, e."timestamp"
        """
    )


def _to_detection(row: dict) -> Detection:
    return Detection(
        detection_id=row["detection_id"],
        event_id=row["event_id"],
        entity_type=row["entity_type"],
        entity_id=row["entity_id"],
        score=float(row["score"]),
        severity=row["severity"],
        signals=[Signal.model_validate(s) for s in row["signals"]],
        mitre=[MitreRef.model_validate(m) for m in row["mitre"]],
    )


def correlate() -> dict:
    rows = _load_unassigned_detections()

    # group by entity, splitting when the gap exceeds the correlation window
    groups: dict[str, list[list[dict]]] = defaultdict(list)
    window = timedelta(minutes=settings.correlation_window_minutes)
    for row in rows:
        key = f"{row['entity_type']}:{row['entity_id']}"
        buckets = groups[key]
        if buckets and (row["timestamp"] - buckets[-1][-1]["timestamp"]) <= window:
            buckets[-1].append(row)
        else:
            buckets.append([row])

    created = 0
    for key, buckets in groups.items():
        for bucket in buckets:
            created += _create_incident(bucket)
    return {"unassigned_detections": len(rows), "incidents_created": created}


def _create_incident(bucket: list[dict]) -> int:
    dets = [_to_detection(r) for r in bucket]
    top = max(dets, key=lambda d: d.score)

    # merge + order techniques by kill chain
    refs: dict[str, MitreRef] = {}
    for d in dets:
        for ref in d.mitre:
            refs[ref.technique_id] = ref
    ordered = sorted(refs.values(), key=lambda r: TACTIC_RANK.get(r.tactic, 99))
    technique_order = [r.technique_id for r in ordered]

    severity = max((d.severity for d in dets), key=lambda s: SEV_RANK[s])
    title = (
        f"{severity.title()} activity on {top.entity_type} '{top.entity_id}' "
        f"— {len(dets)} detection(s), {len(ordered)} technique(s)"
    )

    # narrative from the highest-scoring detection (most evidence)
    narrative, ground = narrate(top)

    rows = pg.query(
        """
        INSERT INTO incidents
            (title, status, severity, entity_type, entity_id, detection_ids, narrative, mitre_chain)
        VALUES (%s, 'open', %s, %s, %s, %s, %s, %s)
        RETURNING incident_id
        """,
        (
            title, severity, top.entity_type, top.entity_id,
            [str(d.detection_id) for d in dets],
            narrative,
            pg.as_jsonb([r.model_dump() for r in ordered]),
        ),
    )
    incident_id = str(rows[0]["incident_id"])

    pg.execute(
        "INSERT INTO audit_log (actor, action, target, detail) VALUES (%s,%s,%s,%s)",
        ("correlator", "incident.create", incident_id,
         pg.as_jsonb({"grounded": ground.ok, "violations": ground.violations})),
    )

    try:
        writer.write_incident(incident_id, severity, top, technique_order)
    except Exception:  # graph is best-effort; never block incident creation
        pass

    return 1
