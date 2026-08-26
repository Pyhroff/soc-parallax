"""Generic JSON / CSV parsers -> UnifiedEvent.

Covers JSON line exports (incl. Elastic/ECS-ish shapes), Wazuh alert JSON, and
flat CSV. Field resolution is best-effort over a set of common aliases.
"""
from __future__ import annotations

import csv as csvmod
import json
from typing import Iterator

from app.schemas.event import (
    EventType,
    LogonInfo,
    NetworkInfo,
    ProcessInfo,
    UnifiedEvent,
)
from app.ingest.parsers.sysmon import _basename, _parse_time, _to_int

# field -> list of candidate keys (checked in order, supports dotted paths)
ALIASES: dict[str, list[str]] = {
    "timestamp": ["timestamp", "@timestamp", "UtcTime", "time", "event.created"],
    "host": ["host", "host.name", "Computer", "agent.name", "hostname"],
    "user": ["user", "user.name", "User", "winlog.event_data.User"],
    "event_type": ["event_type", "event.action", "event.category"],
    "process_name": ["process.name", "Image", "process_name", "winlog.event_data.Image"],
    "cmdline": ["process.command_line", "CommandLine", "cmdline"],
    "parent": ["process.parent.name", "ParentImage", "parent_image"],
    "dest_ip": ["destination.ip", "DestinationIp", "dest_ip", "dst_ip"],
    "dest_port": ["destination.port", "DestinationPort", "dest_port", "dst_port"],
    "domain": ["dns.question.name", "QueryName", "destination.domain", "domain"],
    "logon_type": ["winlog.event_data.LogonType", "LogonType", "logon.type", "logon_type"],
    "src_ip": ["source.ip", "IpAddress", "src_ip"],
}

# crude event_type normalization for free-text categories
TYPE_HINTS = {
    "process": EventType.process_create,
    "network": EventType.network_connect,
    "connection": EventType.network_connect,
    "dns": EventType.dns_query,
    "file": EventType.file_create,
    "authentication": EventType.logon,
    "logon": EventType.logon,
}


def _dig(record: dict, path: str):
    cur = record
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _resolve(record: dict, field: str):
    for key in ALIASES.get(field, []):
        val = record.get(key) if key in record else _dig(record, key)
        if isinstance(val, dict):
            continue  # nested object (e.g. ECS "host":{...}); try dotted alias instead
        if val not in (None, ""):
            return val
    return None


def _classify(record: dict) -> EventType:
    raw = _resolve(record, "event_type")
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if isinstance(raw, str):
        low = raw.lower()
        for hint, etype in TYPE_HINTS.items():
            if hint in low:
                return etype
        try:
            return EventType(low)
        except ValueError:
            pass
    if _resolve(record, "dest_ip"):
        return EventType.network_connect
    if _resolve(record, "process_name"):
        return EventType.process_create
    return EventType.unknown


def event_from_record(record: dict) -> UnifiedEvent:
    etype = _classify(record)
    logon = LogonInfo()
    if etype == EventType.logon:
        logon = LogonInfo(
            type=_to_int(_resolve(record, "logon_type")) or 3,
            result="success",
            src_ip=_resolve(record, "src_ip"),
        )
    ts_raw = _resolve(record, "timestamp")
    return UnifiedEvent(
        timestamp=_parse_time(str(ts_raw) if ts_raw else None),
        source="json",
        event_type=etype,
        host=_resolve(record, "host"),
        user=_resolve(record, "user"),
        process=ProcessInfo(
            name=_basename(_resolve(record, "process_name")),
            parent=_basename(_resolve(record, "parent")),
            cmdline=_resolve(record, "cmdline"),
        ),
        network=NetworkInfo(
            dest_ip=_resolve(record, "dest_ip"),
            dest_port=_to_int(_resolve(record, "dest_port")),
            domain=_resolve(record, "domain"),
        ),
        logon=logon,
        raw=record,
    )


def parse_json_file(path: str) -> Iterator[UnifiedEvent]:
    """Supports a JSON array, JSON-lines, or {'hits': {'hits': [...]}} (Elastic)."""
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read().strip()
    if not content:
        return
    if content[0] == "[":
        records = json.loads(content)
    elif content[0] == "{":
        obj = json.loads(content)
        records = (
            [h.get("_source", h) for h in obj["hits"]["hits"]]
            if "hits" in obj and isinstance(obj["hits"], dict)
            else [obj]
        )
    else:  # JSON lines
        records = [json.loads(line) for line in content.splitlines() if line.strip()]
    for rec in records:
        yield event_from_record(rec)


def parse_csv_file(path: str) -> Iterator[UnifiedEvent]:
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csvmod.DictReader(fh)
        for row in reader:
            rec = {k: v for k, v in row.items() if v not in (None, "")}
            ev = event_from_record(rec)
            ev.source = "csv"
            yield ev
