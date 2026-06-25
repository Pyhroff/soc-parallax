"""Sysmon parser: Windows Event XML / EVTX  ->  UnifiedEvent.

The core mapping function `event_from_fields` is pure (no I/O) so it is unit
testable without an actual .evtx file. `parse_evtx_file` streams real EVTX.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Iterator

from dateutil import parser as dtparser

from app.schemas.event import (
    EventType,
    FileInfo,
    LogonInfo,
    NetworkInfo,
    ProcessInfo,
    UnifiedEvent,
)

# Sysmon Event ID -> our event_type
SYSMON_TYPE_MAP: dict[int, EventType] = {
    1: EventType.process_create,
    3: EventType.network_connect,
    7: EventType.image_load,
    8: EventType.create_remote_thread,
    11: EventType.file_create,
    13: EventType.registry_set,
    22: EventType.dns_query,
}


def _basename(image: str | None) -> str | None:
    if not image:
        return None
    return image.replace("/", "\\").split("\\")[-1]


def _parse_hashes(raw: str | None) -> dict[str, str]:
    # Sysmon Hashes field looks like "SHA256=ABC...,MD5=DEF..."
    out: dict[str, str] = {}
    if not raw:
        return out
    for part in raw.split(","):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip().lower()] = v.strip()
    return out


def _parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        dt = dtparser.parse(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return datetime.now(timezone.utc)


def event_from_fields(event_id: int, data: dict, system: dict | None = None) -> UnifiedEvent:
    """Map a Sysmon record's EventData dict + System dict to a UnifiedEvent."""
    system = system or {}
    etype = SYSMON_TYPE_MAP.get(event_id, EventType.unknown)
    ts = _parse_time(data.get("UtcTime") or system.get("TimeCreated"))
    host = system.get("Computer") or data.get("Computer")
    user = data.get("User")

    process = ProcessInfo(
        name=_basename(data.get("Image")),
        pid=_to_int(data.get("ProcessId")),
        ppid=_to_int(data.get("ParentProcessId")),
        parent=_basename(data.get("ParentImage")),
        cmdline=data.get("CommandLine"),
        hashes=_parse_hashes(data.get("Hashes")),
    )
    network = NetworkInfo(
        dest_ip=data.get("DestinationIp"),
        dest_port=_to_int(data.get("DestinationPort")),
        direction="outbound" if data.get("Initiated") in ("true", "True", True) else None,
        domain=data.get("QueryName") or data.get("DestinationHostname"),
    )
    file = FileInfo(
        path=data.get("TargetFilename"),
        action="create" if etype == EventType.file_create else None,
    )

    return UnifiedEvent(
        timestamp=ts,
        source="sysmon",
        event_type=etype,
        host=host,
        user=user,
        process=process,
        network=network,
        file=file,
        logon=LogonInfo(),
        raw={"EventID": event_id, "EventData": data, "System": system},
    )


def _to_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value), 0) if str(value).lower().startswith("0x") else int(value)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# EVTX streaming (real files from e.g. EVTX-ATTACK-SAMPLES)
# ---------------------------------------------------------------------------
def parse_evtx_file(path: str | os.PathLike) -> Iterator[UnifiedEvent]:
    """Stream a .evtx file and yield UnifiedEvents for Sysmon records.

    Imported lazily so the rest of the app doesn't hard-depend on python-evtx.
    """
    from Evtx.Evtx import Evtx  # type: ignore
    from lxml import etree  # type: ignore

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = etree.fromstring(record.xml().encode("utf-8"))
            except etree.XMLSyntaxError:
                continue

            sys_el = root.find("e:System", ns)
            if sys_el is None:
                continue
            eid_el = sys_el.find("e:EventID", ns)
            if eid_el is None or eid_el.text is None:
                continue
            event_id = int(eid_el.text)
            if event_id not in SYSMON_TYPE_MAP:
                continue  # skip non-behavioral sysmon events

            system = {
                "Computer": _text(sys_el.find("e:Computer", ns)),
                "TimeCreated": _attr(sys_el.find("e:TimeCreated", ns), "SystemTime"),
            }
            data = {
                d.get("Name"): d.text
                for d in root.findall(".//e:EventData/e:Data", ns)
                if d.get("Name")
            }
            yield event_from_fields(event_id, data, system)


def _text(el) -> str | None:
    return el.text if el is not None else None


def _attr(el, name) -> str | None:
    return el.get(name) if el is not None else None
