"""Windows Security log parser  ->  UnifiedEvent.

Handles the auth/account events that Sysmon doesn't: 4624/4625 logon,
4688 process create, 4672 special privileges, 4720 account created.
"""
from __future__ import annotations

from app.schemas.event import EventType, LogonInfo, ProcessInfo, UnifiedEvent
from app.ingest.parsers.sysmon import _basename, _parse_time, _to_int

WINEVENT_TYPE_MAP: dict[int, EventType] = {
    4624: EventType.logon,
    4625: EventType.logon,
    4688: EventType.process_create,
    4672: EventType.privilege_use,
    4720: EventType.account_created,
}


def event_from_fields(event_id: int, data: dict, system: dict | None = None) -> UnifiedEvent:
    system = system or {}
    etype = WINEVENT_TYPE_MAP.get(event_id, EventType.unknown)
    ts = _parse_time(system.get("TimeCreated") or data.get("UtcTime"))
    host = system.get("Computer")
    # Account name fields differ across event ids
    user = (
        data.get("TargetUserName")
        or data.get("SubjectUserName")
        or data.get("AccountName")
    )
    domain = data.get("TargetDomainName") or data.get("SubjectDomainName")
    if user and domain:
        user = f"{domain}\\{user}"

    logon = LogonInfo()
    process = ProcessInfo()

    if etype == EventType.logon:
        logon = LogonInfo(
            type=_to_int(data.get("LogonType")),
            result="success" if event_id == 4624 else "failure",
            src_ip=data.get("IpAddress"),
        )
    elif etype == EventType.process_create:
        process = ProcessInfo(
            name=_basename(data.get("NewProcessName")),
            pid=_to_int(data.get("NewProcessId")),
            parent=_basename(data.get("ParentProcessName")),
            cmdline=data.get("CommandLine"),
        )

    return UnifiedEvent(
        timestamp=ts,
        source="winevent",
        event_type=etype,
        host=host,
        user=user,
        process=process,
        logon=logon,
        raw={"EventID": event_id, "EventData": data, "System": system},
    )
