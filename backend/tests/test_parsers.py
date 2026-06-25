"""Parser mapping tests — no DB, no files needed (pure functions)."""
from app.ingest.parsers import sysmon, winevent
from app.ingest.parsers.generic import event_from_record
from app.schemas.event import EventType


def test_sysmon_process_create():
    data = {
        "UtcTime": "2026-06-08 02:14:01.123",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell -enc ZQBjAGgAbwA=",
        "ParentImage": r"C:\Program Files\Microsoft Office\winword.exe",
        "ProcessId": "4821",
        "ParentProcessId": "992",
        "Hashes": "SHA256=ABC123,MD5=DEF456",
        "User": "ACME\\jdoe",
    }
    ev = sysmon.event_from_fields(1, data, {"Computer": "WS-07"})
    assert ev.event_type == EventType.process_create
    assert ev.process.name == "powershell.exe"
    assert ev.process.parent == "winword.exe"
    assert ev.process.hashes["sha256"] == "ABC123"
    assert ev.host == "WS-07"
    assert ev.user == "ACME\\jdoe"
    assert ev.timestamp.hour == 2


def test_sysmon_network_connect():
    data = {"DestinationIp": "185.220.101.5", "DestinationPort": "443",
            "Image": r"C:\...\powershell.exe", "Initiated": "true"}
    ev = sysmon.event_from_fields(3, data)
    assert ev.event_type == EventType.network_connect
    assert ev.network.dest_ip == "185.220.101.5"
    assert ev.network.dest_port == 443
    assert ev.network.direction == "outbound"


def test_winevent_logon():
    data = {"LogonType": "3", "TargetUserName": "jdoe", "TargetDomainName": "ACME",
            "IpAddress": "10.0.0.9"}
    ev = winevent.event_from_fields(4624, data, {"Computer": "WS-07"})
    assert ev.event_type == EventType.logon
    assert ev.logon.type == 3
    assert ev.logon.result == "success"
    assert ev.user == "ACME\\jdoe"


def test_generic_ecs_record():
    rec = {
        "@timestamp": "2026-06-08T02:14:01Z",
        "host": {"name": "WS-07"},
        "user": {"name": "jdoe"},
        "process": {"name": "powershell.exe", "command_line": "powershell -enc x"},
        "event": {"category": ["process"]},
    }
    ev = event_from_record(rec)
    assert ev.host == "WS-07"
    assert ev.process.name == "powershell.exe"
    assert ev.event_type == EventType.process_create
