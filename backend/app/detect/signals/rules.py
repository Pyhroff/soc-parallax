"""Contextual detection rules.

These are deterministic, attacker-behavior patterns that don't need a baseline
(they're suspicious regardless of history). Each returns a RuleHit or None.
Every rule maps to a MITRE technique via mitre.yaml using its `name`.
"""
from __future__ import annotations

import re
from typing import NamedTuple

from app.schemas.event import EventType, UnifiedEvent


class RuleHit(NamedTuple):
    name: str          # must match a key in mitre.yaml signal_map
    sub_score: float   # 0..1
    evidence: str


# Office apps that should rarely spawn a shell/script interpreter
OFFICE_PROCS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
# Living-off-the-land binaries commonly abused
LOLBINS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe",
           "bitsadmin.exe", "msbuild.exe", "installutil.exe"}
CRED_TOOLS = {"mimikatz.exe", "procdump.exe", "lsass.exe"}
ENCODED_PS = re.compile(r"-e(nc(odedcommand)?)?\b", re.IGNORECASE)
DOWNLOAD_PAT = re.compile(
    r"(downloadstring|downloadfile|invoke-webrequest|iwr|bitsadmin|certutil.+-urlcache|"
    r"new-object\s+net\.webclient)", re.IGNORECASE)


def evaluate(ev: UnifiedEvent) -> list[RuleHit]:
    hits: list[RuleHit] = []
    proc = (ev.process.name or "").lower()
    parent = (ev.process.parent or "").lower()
    cmd = ev.process.cmdline or ""

    if ev.event_type == EventType.process_create:
        # Office application spawning a shell -> classic phishing payload
        if parent in OFFICE_PROCS and proc in SHELLS:
            hits.append(RuleHit("rule:office_spawn_shell", 0.9,
                                f"{parent} spawned {proc} — office app launching a shell"))
        # Encoded PowerShell
        if proc in {"powershell.exe", "pwsh.exe"} and ENCODED_PS.search(cmd) and "-" in cmd:
            hits.append(RuleHit("rule:encoded_powershell", 0.85,
                                "PowerShell launched with an encoded command (-enc)"))
        # In-line download cradle
        if DOWNLOAD_PAT.search(cmd):
            hits.append(RuleHit("rule:cmd_download", 0.75,
                                "Command line contains a remote download cradle"))
        # LOLBin execution
        if proc in LOLBINS:
            hits.append(RuleHit("rule:lolbin_execution", 0.6,
                                f"Execution via known LOLBin {proc}"))
        # Suspicious non-office parent for a shell (e.g. services.exe -> cmd)
        if proc in SHELLS and parent and parent not in OFFICE_PROCS and parent in {
            "services.exe", "wmiprvse.exe", "sqlservr.exe", "w3wp.exe"
        }:
            hits.append(RuleHit("rule:suspicious_parent", 0.7,
                                f"{parent} spawned {proc} — unusual service-to-shell chain"))
        # Credential dumping tooling
        if proc in CRED_TOOLS or "sekurlsa" in cmd.lower():
            hits.append(RuleHit("rule:credential_tool", 0.9,
                                "Credential-dumping tool/argument observed"))
        # Scheduled task creation
        if proc == "schtasks.exe" and "/create" in cmd.lower():
            hits.append(RuleHit("rule:scheduled_task", 0.6,
                                "Scheduled task creation (possible persistence)"))
        # Remote execution tooling
        if proc in {"psexec.exe", "psexesvc.exe", "wmic.exe"} and "process call create" in cmd.lower():
            hits.append(RuleHit("rule:remote_exec", 0.7,
                                "Remote process execution (possible lateral movement)"))

    if ev.event_type == EventType.registry_set:
        target = (ev.raw.get("EventData", {}) or {}).get("TargetObject", "").lower()
        if "currentversion\\run" in target or "currentversion\\runonce" in target:
            hits.append(RuleHit("rule:autostart_registry", 0.65,
                                "Autostart (Run key) registry modification — persistence"))

    return hits
