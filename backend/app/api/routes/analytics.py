"""Baseline, detection, incident, investigation, and graph endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Query

from app.baseline.engine import build_baselines, get_baseline
from app.correlate.incidents import correlate
from app.db import postgres as pg
from app.detect.scorer import run_detection_over_events
from app.graph import queries as gq
from app.investigate.graph import run_investigation

router = APIRouter(tags=["analytics"])


# ---- baselines ----
@router.post("/baseline/build")
def baseline_build(days: int | None = Body(None, embed=True)) -> dict:
    return build_baselines(days)


@router.get("/baseline")
def baseline_get(entity_type: str, entity_id: str, feature: str) -> dict:
    bl = get_baseline(entity_type, entity_id, feature)
    if not bl:
        raise HTTPException(404, "No baseline for that entity/feature")
    return bl


# ---- detections ----
@router.post("/detect/run")
def detect_run(min_severity: str = Body("low", embed=True)) -> dict:
    return run_detection_over_events(min_severity)


@router.get("/detections")
def detections_list(severity: str | None = None, limit: int = Query(100, le=1000)) -> list[dict]:
    where = "WHERE severity=%s" if severity else ""
    params: tuple = (severity, limit) if severity else (limit,)
    return pg.query(
        f"""SELECT detection_id, event_id, entity_type, entity_id, score, severity,
                   signals, mitre, created_at
            FROM detections {where} ORDER BY score DESC, created_at DESC LIMIT %s""",
        params,
    )


# ---- incidents ----
@router.post("/correlate/run")
def correlate_run() -> dict:
    return correlate()


@router.get("/incidents")
def incidents_list(status: str | None = None, limit: int = Query(100, le=1000)) -> list[dict]:
    where = "WHERE status=%s" if status else ""
    params: tuple = (status, limit) if status else (limit,)
    return pg.query(
        f"""SELECT incident_id, title, status, severity, entity_type, entity_id,
                   detection_ids, mitre_chain, created_at
            FROM incidents {where} ORDER BY created_at DESC LIMIT %s""",
        params,
    )


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: str) -> dict:
    rows = pg.query("SELECT * FROM incidents WHERE incident_id=%s", (incident_id,))
    if not rows:
        raise HTTPException(404, "Incident not found")
    inc = rows[0]
    inc["detections"] = pg.query(
        """SELECT d.*, e."timestamp", e.payload
           FROM detections d JOIN events e ON e.event_id=d.event_id
           WHERE d.detection_id = ANY(%s) ORDER BY e."timestamp" """,
        (inc["detection_ids"],),
    )
    try:
        inc["graph"] = gq.subgraph_for_incident(incident_id)
        inc["similar"] = gq.similar_incidents(incident_id)
    except Exception:
        inc["graph"], inc["similar"] = {"nodes": []}, []
    return inc


# ---- investigation ----
@router.post("/investigate")
def investigate(entity_type: str = Body(...), entity_id: str = Body(...),
                window_hours: int = Body(24)) -> dict:
    if entity_type not in ("user", "host"):
        raise HTTPException(400, "entity_type must be 'user' or 'host'")
    return run_investigation(entity_type, entity_id, window_hours)


# ---- graph / predictions ----
@router.get("/graph/blast-radius")
def graph_blast(entity: str) -> list[dict]:
    return gq.blast_radius(entity)


@router.get("/predict/next")
def predict_next(technique_id: str) -> list[dict]:
    return gq.likely_next_techniques(technique_id)


# ---- overview stats ----
@router.get("/overview")
def overview() -> dict:
    def scalar(sql: str):
        r = pg.query(sql)
        return list(r[0].values())[0] if r else 0

    by_sev = pg.query("SELECT severity, count(*) AS n FROM detections GROUP BY severity")
    top_tech = pg.query(
        """SELECT m->>'technique_id' AS technique_id, m->>'name' AS name, count(*) AS n
           FROM detections, jsonb_array_elements(mitre) AS m
           GROUP BY 1,2 ORDER BY n DESC LIMIT 10"""
    )
    return {
        "events": scalar("SELECT count(*) FROM events"),
        "detections": scalar("SELECT count(*) FROM detections"),
        "incidents": scalar("SELECT count(*) FROM incidents"),
        "open_incidents": scalar("SELECT count(*) FROM incidents WHERE status='open'"),
        "detections_by_severity": {r["severity"]: r["n"] for r in by_sev},
        "top_techniques": top_tech,
    }
