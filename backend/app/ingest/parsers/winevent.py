"""Windows Security log parser  ->  UnifiedEvent.

Handles the auth/account events that Sysmon doesn't: 4624/4625 logon,
4688 process create, 4672 special privileges, 4720 account created.
"""
from __future__ import annotations

from app.schemas.event import EventType, LogonInfo, NetworkInfo, ProcessInfo, UnifiedEvent
from app.ingest.parsers.sysmon import _basename, _parse_time, _to_int

WINEVENT_TYPE_MAP: dict[int, EventType] = {
    4624: EventType.logon,
    4625: EventType.logon,
    4688: EventType.process_create,
    4672: EventType.privilege_use,
    4720: EventType.account_created,
    4648: EventType.logon,          # explicit-credential logon
    4768: EventType.logon,          # Kerberos TGT request
    4771: EventType.logon,          # Kerberos pre-auth failure
    4776: EventType.logon,          # NTLM credential validation
    4697: EventType.service_install,
    4698: EventType.scheduled_task,
    4702: EventType.scheduled_task,
    5156: EventType.network_connect,
    4662: EventType.object_access,   # directory service object operation (DCSync)
    5145: EventType.object_access,   # network share object access
    1102: EventType.log_cleared,     # audit log cleared
}
_FAILURE_IDS = {4625, 4771}


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
            result="failure" if event_id in _FAILURE_IDS else "success",
            src_ip=data.get("IpAddress"),
        )
    elif etype == EventType.process_create:
        process = ProcessInfo(
            name=_basename(data.get("NewProcessName")),
            pid=_to_int(data.get("NewProcessId")),
            parent=_basename(data.get("ParentProcessName")),
            cmdline=data.get("CommandLine"),
            image_path=data.get("NewProcessName"),
        )

    network = NetworkInfo()
    if etype == EventType.network_connect:
        process = ProcessInfo(name=_basename(data.get("Application")), image_path=data.get("Application"))
        network = NetworkInfo(dest_ip=data.get("DestAddress"), dest_port=_to_int(data.get("DestPort")),
                              direction="inbound" if data.get("Direction") == "%%14592" else "outbound")
    elif etype == EventType.logon and not logon.src_ip:
        logon = LogonInfo(type=logon.type, result=logon.result,
                          src_ip=data.get("IpAddress") or data.get("ClientAddress"))

    return UnifiedEvent(
        timestamp=ts,
        source="winevent",
        event_type=etype,
        host=host,
        user=user,
        process=process,
        network=network,
        logon=logon,
        raw={"EventID": event_id, "EventData": data, "System": system},
    )


def powershell_event_from_fields(event_id: int, data: dict, system: dict | None = None) -> UnifiedEvent:
    """PowerShell 4104: the text of a script block that was executed."""
    system = system or {}
    return UnifiedEvent(
        timestamp=_parse_time(system.get("TimeCreated")), source="powershell",
        event_type=EventType.script_block, host=system.get("Computer"),
        process=ProcessInfo(name="powershell.exe"),
        raw={"EventID": event_id, "EventData": data, "System": system},
    )


def service_event_from_fields(event_id: int, data: dict, system: dict | None = None) -> UnifiedEvent:
    """System 7045: a service was installed (ServiceName, ImagePath)."""
    system = system or {}
    return UnifiedEvent(
        timestamp=_parse_time(system.get("TimeCreated")), source="scm",
        event_type=EventType.service_install, host=system.get("Computer"),
        raw={"EventID": event_id, "EventData": data, "System": system},
    )


def log_cleared_event_from_fields(event_id: int, data: dict, system: dict | None = None) -> UnifiedEvent:
    """Eventlog 1102 (provider Microsoft-Windows-Eventlog): the audit log was cleared."""
    system = system or {}
    return UnifiedEvent(
        timestamp=_parse_time(system.get("TimeCreated")), source="eventlog",
        event_type=EventType.log_cleared, host=system.get("Computer"),
        raw={"EventID": event_id, "EventData": data, "System": system},
    )
