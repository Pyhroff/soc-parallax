"""Ingestion endpoints. File access is confined to INGEST_ROOT; all routes need
the ingest role (baseline training in /pipeline additionally needs admin)."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Body, Depends, HTTPException

from app.api.auth import require
from app.baseline.engine import build_baselines
from app.config import settings
from app.correlate.incidents import correlate
from app.detect.scorer import run_detection_over_events
from app.graph import writer
from app.ingest import safe_paths
from app.ingest.parsers.generic import event_from_record
from app.ingest.store import ingest_file, store_events

log = logging.getLogger("parallax.ingest")
router = APIRouter(prefix="/ingest", tags=["ingest"], dependencies=[Depends(require("ingest"))])

DATASETS = ("baseline", "observed")


def _resolve(path: str) -> str:
    try:
        return safe_paths.resolve_inside_root(path)
    except safe_paths.PathRejected as exc:
        log.warning("ingest path rejected: %r (%s)", path, exc)
        raise HTTPException(400, str(exc)) from None


@router.post("/file")
def ingest_single_file(path: str = Body(..., embed=True), dataset: str = Body("observed")) -> dict:
    if dataset not in DATASETS:
        raise HTTPException(400, "dataset must be 'baseline' or 'observed'")
    full = _resolve(path)
    try:
        safe_paths.check_file(full)
    except safe_paths.PathRejected as exc:
        raise HTTPException(400, str(exc)) from None
    try:
        count = ingest_file(full, dataset)
    except Exception:
        log.exception("ingest failed: %s", full)
        raise HTTPException(422, "could not parse file") from None
    return {"ingested": count, "path": path, "dataset": dataset}


@router.post("/dir")
def ingest_directory(path: str = Body(..., embed=True), dataset: str = Body("observed")) -> dict:
    if dataset not in DATASETS:
        raise HTTPException(400, "dataset must be 'baseline' or 'observed'")
    full = _resolve(path)
    try:
        files = safe_paths.list_files(full)
    except safe_paths.PathRejected as exc:
        raise HTTPException(400, str(exc)) from None
    total, errors = 0, []
    for f in files:
        try:
            safe_paths.check_file(f)
            total += ingest_file(f, dataset)
        except Exception as exc:
            log.warning("skip %s: %s", f, exc)
            errors.append({"file": f[len(settings.ingest_root):].lstrip("/\\"), "error": "skipped"})
    return {"files": len(files), "ingested": total, "errors": errors, "dataset": dataset}


@router.post("/records")
def ingest_records(records: list[dict] = Body(...)) -> dict:
    """Ingest already-shaped JSON records (e.g. live forwarder)."""
    if len(records) > settings.max_records_per_request:
        raise HTTPException(413, f"at most {settings.max_records_per_request} records per request")
    events = [event_from_record(r) for r in records]
    count = store_events(events, "observed")       # live records can never be training data
    for ev in events:
        try:
            writer.write_event(ev)
        except Exception:
            log.warning("graph write failed for %s", ev.event_id, exc_info=True)
    return {"ingested": count}


@router.post("/pipeline", dependencies=[Depends(require("admin"))])
def full_pipeline(path: str = Body(..., embed=True), train: bool = Body(False)) -> dict:
    """ingest dir -> (optionally build baselines from dataset='baseline') -> detect -> correlate.

    train defaults to False: baselines are only built from data explicitly labelled
    'baseline', never from whatever was just ingested.
    """
    ingest = ingest_directory(path, "observed")
    baseline = build_baselines() if train else {"skipped": True}
    detect = run_detection_over_events()
    incidents = correlate()
    return {"ingest": ingest, "baseline": baseline, "detect": detect, "correlate": incidents}
