"""Persist UnifiedEvents to Postgres and dispatch files to the right parser."""
from __future__ import annotations

import os
from typing import Iterable, Iterator

from app.db import postgres as pg
from app.ingest.parsers import generic, sysmon
from app.schemas.event import UnifiedEvent

_INSERT = """
INSERT INTO events
    (event_id, "timestamp", source, event_type, host, "user",
     process_name, cmdline, dest_ip, dest_port, payload)
VALUES
    (%(event_id)s, %(timestamp)s, %(source)s, %(event_type)s, %(host)s, %(user)s,
     %(process_name)s, %(cmdline)s, %(dest_ip)s, %(dest_port)s, %(payload)s)
ON CONFLICT (event_id) DO NOTHING
"""


def store_events(events: Iterable[UnifiedEvent]) -> int:
    """Bulk insert. Returns count inserted/attempted."""
    rows = []
    for ev in events:
        cols = ev.flat_columns()
        cols["payload"] = pg.as_jsonb(ev.model_dump(mode="json"))
        # dest_ip may be a bare hostname in some logs; keep INET clean
        if cols["dest_ip"] and not _looks_like_ip(cols["dest_ip"]):
            cols["dest_ip"] = None
        rows.append(cols)

    if not rows:
        return 0

    with pg.get_conn() as conn:
        with conn.cursor() as cur:
            cur.executemany(_INSERT, rows)
        conn.commit()
    return len(rows)


def ingest_file(path: str) -> int:
    """Detect file type by extension and ingest. Returns events stored."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".evtx":
        events: Iterator[UnifiedEvent] = sysmon.parse_evtx_file(path)
    elif ext == ".json" or ext == ".ndjson":
        events = generic.parse_json_file(path)
    elif ext == ".csv":
        events = generic.parse_csv_file(path)
    else:
        raise ValueError(f"Unsupported file type: {ext}")
    return store_events(events)


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in value  # crude IPv6 check
