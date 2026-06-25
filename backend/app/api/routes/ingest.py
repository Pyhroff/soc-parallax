"""Ingestion endpoints."""
from __future__ import annotations

import glob
import os

from fastapi import APIRouter, Body, HTTPException

from app.baseline.engine import build_baselines
from app.correlate.incidents import correlate
from app.detect.scorer import run_detection_over_events
from app.ingest.store import ingest_file, store_events
from app.ingest.parsers.generic import event_from_record
from app.graph import writer

router = APIRouter(prefix="/ingest", tags=["ingest"])


@router.post("/file")
def ingest_single_file(path: str = Body(..., embed=True)) -> dict:
    if not os.path.exists(path):
        raise HTTPException(404, f"File not found: {path}")
    count = ingest_file(path)
    return {"ingested": count, "path": path}


@router.post("/dir")
def ingest_directory(path: str = Body(..., embed=True)) -> dict:
    if not os.path.isdir(path):
        raise HTTPException(404, f"Directory not found: {path}")
    files = []
    for ext in ("*.evtx", "*.json", "*.ndjson", "*.csv"):
        files.extend(glob.glob(os.path.join(path, "**", ext), recursive=True))
    total = 0
    errors = []
    for f in files:
        try:
            total += ingest_file(f)
        except Exception as exc:
            errors.append({"file": f, "error": str(exc)})
    return {"files": len(files), "ingested": total, "errors": errors}


@router.post("/records")
def ingest_records(records: list[dict] = Body(...)) -> dict:
    """Ingest already-shaped JSON records (e.g. live forwarder)."""
    events = [event_from_record(r) for r in records]
    count = store_events(events)
    for ev in events:
        try:
            writer.write_event(ev)
        except Exception:
            pass
    return {"ingested": count}


@router.post("/pipeline")
def full_pipeline(path: str = Body(..., embed=True), train: bool = Body(True)) -> dict:
    """End-to-end: ingest dir -> (build baselines) -> detect -> correlate."""
    if not os.path.isdir(path):
        raise HTTPException(404, f"Directory not found: {path}")
    ingest = ingest_directory(path)
    baseline = build_baselines() if train else {"skipped": True}
    detect = run_detection_over_events()
    incidents = correlate()
    return {"ingest": ingest, "baseline": baseline, "detect": detect, "correlate": incidents}
