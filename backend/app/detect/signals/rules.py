"""Contextual detection rules.

Deterministic attacker-behavior patterns that don't need a baseline. Each rule
returns a RuleHit with a name that must exist in mitre.yaml's signal_map.

Design notes (each was a real false-negative or false-positive found in review):
  * Command lines are tokenized; PowerShell accepts any unambiguous prefix of
    -EncodedCommand (-e, -ec, -en, -enc, ...), so matching only "-enc" is evadable.
  * Rules key on the *effective* binary: Sysmon's OriginalFileName when present, so
    copying powershell.exe to p.exe does not hide it (and is itself a finding).
  * LOLBin rules fire on abuse patterns (arguments / parent), not on the binary's
    mere existence: `certutil -hashfile`, or MSBuild started by Visual Studio, are
    ordinary.
  * `lsass.exe` creating as a process is the OS booting, not credential theft.
"""
from __future__ import annotations

import re
from typing import NamedTuple

from app.schemas.event import EventType, UnifiedEvent


class RuleHit(NamedTuple):
    name: str          # must match a key in mitre.yaml signal_map
    sub_score: float   # 0..1
    evidence: str


OFFICE_PROCS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe"}
SERVER_PARENTS = {"w3wp.exe", "sqlservr.exe", "wmiprvse.exe", "httpd.exe", "php-cgi.exe", "nginx.exe"}
DEV_PARENTS = {"devenv.exe", "dotnet.exe", "msbuild.exe", "code.exe", "rider64.exe", "vbcscompiler.exe"}

_USER_WRITABLE = r"\\(appdata|temp|users\\public|downloads|programdata)\\"
# binary -> regex over the command line that makes its use suspicious (None = always)
LOLBINS: dict[str, re.Pattern | None] = {
    "rundll32.exe": re.compile(rf"(javascript:|vbscript:|https?://|comsvcs\.dll|{_USER_WRITABLE})", re.I),
    "regsvr32.exe": re.compile(r"(/i:\s*https?|scrobj\.dll|https?://|\.sct\b)", re.I),
    "mshta.exe": None,
    "certutil.exe": re.compile(r"(-urlcache|-decode\b|-decodehex|-encode\b|-verifyctl)", re.I),
    "bitsadmin.exe": re.compile(r"(/transfer|/addfile|/setnotifycmdline)", re.I),
    "msbuild.exe": re.compile(rf"(https?://|{_USER_WRITABLE})", re.I),
    "installutil.exe": re.compile(r"(/logtoconsole=false|/logfile=\s)", re.I),
}
LOLBIN_NAMES = set(LOLBINS)

CRED_TOOLS = {"mimikatz.exe"}
CRED_ARGS = re.compile(r"(sekurlsa|lsadump::|comsvcs\.dll.*minidump|procdump.*lsass|-ma\s+lsass)", re.I)
REMOTE_EXEC_TOOLS = {"psexec.exe", "psexec64.exe", "psexesvc.exe", "paexec.exe"}

# system binaries that must live in System32 (a copy elsewhere is masquerading)
SYSTEM32_ONLY = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
                 "smss.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe"}

DOWNLOAD_PAT = re.compile(
    r"(downloadstring|downloadfile|invoke-webrequest|\biwr\b|\bwget\b|\bcurl(\.exe)?\b.+https?://|"
    r"bitsadmin.+/transfer|certutil.+-urlcache|new-object\s+net\.webclient|start-bitstransfer)",
    re.IGNORECASE)
_TOKEN = re.compile(r'"[^"]*"|\S+')
_ENC_FULL = "encodedcommand"


def _tokens(cmd: str) -> list[str]:
    return _TOKEN.findall(cmd or "")


def is_encoded_powershell(cmd: str) -> bool:
    """True if the command line passes -EncodedCommand in any accepted spelling."""
    toks = _tokens(cmd)
    for i, tok in enumerate(toks[1:], start=1):
        if tok[0] in "-/" and len(tok) >= 2:
            flag = tok[1:].lower()
            if flag and (_ENC_FULL.startswith(flag) or flag == "ec") and i + 1 < len(toks):
                return True
    return False


SCRIPT_CRED = re.compile(r"(invoke-mimikatz|mimikatz|minidumpwritedump|sekurlsa|dumpcreds|lsass)", re.I)
SCRIPT_AMSI = re.compile(r"(amsiutils|amsiinitfailed|amsicontext|amsi\.dll)", re.I)
SCRIPT_ENCODED = re.compile(r"frombase64string.{0,200}(iex|invoke-expression)|"
                            r"(iex|invoke-expression).{0,200}frombase64string",
                            re.I | re.S)
TASK_RISKY = re.compile(r"(cmd(\.exe)?\s*/c|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|"
                        r"[\\/](appdata|temp|users[\\/]public|programdata)[\\/])", re.I)
SERVICE_RISKY = re.compile(r"(%comspec%|cmd(\.exe)?\s*/c|powershell|pwsh|mshta|psexesvc|"
                           r"[\\/](appdata|temp|users[\\/]public|programdata)[\\/])", re.I)
DCSYNC_GUIDS = re.compile(r"(1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|"
                          r"89e95b76-444d-4c62-991a-0facbeda640c)", re.I)
ADMIN_SHARES = {"\\\\*\\ADMIN$", "\\\\*\\C$"}
LSASS_READ_MASK = 0x0010           # PROCESS_VM_READ
PROC_ACCESS_BENIGN_SOURCES = {"csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "svchost.exe",
                              "lsass.exe", "msmpeng.exe", "mssense.exe", "wmiprvse.exe", "taskmgr.exe",
                              "vmtoolsd.exe", "werfault.exe", "sysmon.exe", "sysmon64.exe"}
INJECT_BENIGN_SOURCES = {"csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "svchost.exe",
                         "msmpeng.exe", "vmtoolsd.exe", "explorer.exe", "searchindexer.exe"}


def _evtdata(ev: UnifiedEvent) -> dict:
    return ev.raw.get("EventData", {}) or {}


def _evaluate_other(ev: UnifiedEvent) -> list[RuleHit]:
    """Rules for non-process events: script blocks, tasks, services, process access, remote threads."""
    hits: list[RuleHit] = []
    d = _evtdata(ev)
    if ev.event_type == EventType.script_block:
        text = str(d.get("ScriptBlockText", ""))
        if SCRIPT_CRED.search(text):
            hits.append(RuleHit("rule:credential_tool", 0.9, "PowerShell script block references credential dumping"))
        if SCRIPT_AMSI.search(text):
            hits.append(RuleHit("rule:amsi_bypass", 0.85, "PowerShell script block tampers with AMSI"))
        if DOWNLOAD_PAT.search(text):
            hits.append(RuleHit("rule:cmd_download", 0.75, "PowerShell script block contains a download cradle"))
        if SCRIPT_ENCODED.search(text):
            hits.append(RuleHit("rule:encoded_powershell", 0.85, "PowerShell script block decodes and executes base64"))
    elif ev.event_type == EventType.scheduled_task:
        content = str(d.get("TaskContent", ""))
        if TASK_RISKY.search(content):
            hits.append(RuleHit("rule:scheduled_task", 0.7,
                                f"Scheduled task '{d.get('TaskName', '?')}' runs a shell or writable path"))
    elif ev.event_type == EventType.service_install:
        path = str(d.get("ImagePath") or d.get("ServiceFileName") or "")
        if SERVICE_RISKY.search(path):
            hits.append(RuleHit("rule:service_install", 0.8,
                                f"Service '{d.get('ServiceName', '?')}' installed with a suspicious image path"))
        if "psexesvc" in path.lower():
            hits.append(RuleHit("rule:remote_exec", 0.7, "PsExec service installed (possible lateral movement)"))
    elif ev.event_type == EventType.log_cleared:
        hits.append(RuleHit("rule:log_cleared", 0.8, "An audit/event log was cleared"))
    elif ev.event_type == EventType.object_access:
        eid = ev.raw.get("EventID")
        if eid == 4662 and DCSYNC_GUIDS.search(str(d.get("Properties", ""))) \
                and not str(d.get("SubjectUserName", "")).endswith("$"):
            hits.append(RuleHit("rule:dcsync", 0.9, "Directory replication rights used by a non-machine account"))
        elif eid == 5145 and str(d.get("ShareName", "")).upper().rstrip("\\") in ADMIN_SHARES \
                and not str(d.get("SubjectUserName", "")).endswith("$") \
                and "WRITE" in str(d.get("AccessList", "")).upper():
            hits.append(RuleHit("rule:admin_share_write", 0.7,
                                f"Write access to administrative share {d.get('ShareName')} by a user account"))
    elif ev.event_type == EventType.process_access:
        src = (d.get("SourceImage") or "").replace("/", "\\").split("\\")[-1].lower()
        target = (d.get("TargetImage") or "").lower()
        try:
            mask = int(str(d.get("GrantedAccess", "0")), 16)
        except ValueError:
            mask = 0
        if target.endswith("\\lsass.exe") and mask & LSASS_READ_MASK and src not in PROC_ACCESS_BENIGN_SOURCES:
            hits.append(RuleHit("rule:credential_tool", 0.9,
                                f"{src or '?'} opened lsass.exe with memory-read access ({d.get('GrantedAccess')})"))
    elif ev.event_type == EventType.create_remote_thread:
        src = (d.get("SourceImage") or "").replace("/", "\\").split("\\")[-1].lower()
        if src and src not in INJECT_BENIGN_SOURCES:
            hits.append(RuleHit("rule:process_injection", 0.7,
                                f"{src} created a remote thread in {(d.get('TargetImage') or '?')}"))
    return hits


def evaluate(ev: UnifiedEvent) -> list[RuleHit]:
    hits: list[RuleHit] = _evaluate_other(ev)
    shown = (ev.process.name or "").lower()
    original = (ev.process.original_name or "").lower()
    proc = original or shown                      # effective binary
    parent = (ev.process.parent or "").lower()
    cmd = ev.process.cmdline or ""
    path = (ev.process.image_path or "").lower().replace("/", "\\")

    if ev.event_type == EventType.process_create:
        if original and shown and original != shown:
            hits.append(RuleHit("rule:renamed_binary", 0.7,
                                f"{shown} is really {original} (original filename differs from the image name)"))

        if shown in SYSTEM32_ONLY and path and "\\windows\\system32\\" not in path \
                and "\\windows\\syswow64\\" not in path:
            hits.append(RuleHit("rule:system_binary_wrong_path", 0.8,
                                f"{shown} running from {ev.process.image_path} instead of System32"))

        if parent in OFFICE_PROCS and (proc in SHELLS or proc in LOLBIN_NAMES):
            hits.append(RuleHit("rule:office_spawn_shell", 0.9,
                                f"{parent} spawned {proc} — office app launching a shell/script host"))

        if proc in {"powershell.exe", "pwsh.exe"} and is_encoded_powershell(cmd):
            hits.append(RuleHit("rule:encoded_powershell", 0.85,
                                "PowerShell launched with an encoded command"))

        if DOWNLOAD_PAT.search(cmd):
            hits.append(RuleHit("rule:cmd_download", 0.75,
                                "Command line contains a remote download cradle"))

        if proc in LOLBINS:
            pat = LOLBINS[proc]
            if pat is None:
                hits.append(RuleHit("rule:lolbin_execution", 0.6, f"Execution of script-proxy binary {proc}"))
            elif pat.search(cmd):
                hits.append(RuleHit("rule:lolbin_execution", 0.6,
                                    f"{proc} used with an abuse pattern in its arguments"))
            elif parent in OFFICE_PROCS | (SCRIPT_HOSTS - {"powershell.exe", "pwsh.exe"}):
                hits.append(RuleHit("rule:lolbin_execution", 0.6,
                                    f"{proc} launched by {parent}"))
            if proc == "msbuild.exe" and parent in DEV_PARENTS:
                hits = [h for h in hits if not (h.name == "rule:lolbin_execution")]

        if proc in SHELLS and parent in SERVER_PARENTS:
            hits.append(RuleHit("rule:suspicious_parent", 0.7,
                                f"{parent} spawned {proc} — server process launching a shell"))

        if proc in CRED_TOOLS or CRED_ARGS.search(cmd):
            hits.append(RuleHit("rule:credential_tool", 0.9,
                                "Credential-dumping tool or argument observed"))

        if proc == "schtasks.exe" and "/create" in cmd.lower():
            hits.append(RuleHit("rule:scheduled_task", 0.6,
                                "Scheduled task creation (possible persistence)"))

        if proc in REMOTE_EXEC_TOOLS or (proc == "wmic.exe" and "process call create" in cmd.lower()
                                         and "/node" in cmd.lower()):
            hits.append(RuleHit("rule:remote_exec", 0.7,
                                "Remote process execution tooling (possible lateral movement)"))

    if ev.event_type == EventType.registry_set:
        target = str((ev.raw.get("EventData", {}) or {}).get("TargetObject", "")).lower()
        if "currentversion\\run" in target or "currentversion\\runonce" in target:
            hits.append(RuleHit("rule:autostart_registry", 0.65,
                                "Autostart (Run key) registry modification — persistence"))

    return hits
