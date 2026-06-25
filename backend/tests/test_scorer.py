"""Scorer tests — the ones that matter in an interview: a true positive and a
false positive, with an explanation of why each scored the way it did.

No DB: we monkeypatch get_baseline so tests are hermetic.
"""
import app.detect.scorer as scorer
from app.ingest.parsers import sysmon


def _common_baseline(value_counts):
    return {"distribution": value_counts, "sample_count": sum(value_counts.values()),
            "first_seen": None, "last_seen": None}


def test_true_positive_office_spawns_encoded_powershell(monkeypatch):
    """winword.exe -> powershell.exe -enc, user has never run PowerShell."""
    # baseline: user normally runs office apps, never powershell
    def fake_baseline(etype, eid, feature):
        if feature == "process_name":
            return _common_baseline({"winword.exe": 400, "outlook.exe": 300, "chrome.exe": 300})
        if feature == "parent_child":
            return _common_baseline({"explorer.exe->winword.exe": 200})
        return None
    monkeypatch.setattr(scorer, "get_baseline", fake_baseline)

    data = {
        "UtcTime": "2026-06-08 02:14:01",
        "Image": r"C:\...\powershell.exe",
        "CommandLine": "powershell -enc ZQBjAGgAbwA=",
        "ParentImage": r"C:\...\winword.exe",
        "User": "ACME\\jdoe",
    }
    ev = sysmon.event_from_fields(1, data, {"Computer": "WS-07"})
    det = scorer.score_event(ev)

    assert det is not None
    assert det.severity in ("high", "critical")
    names = {s.name for s in det.signals}
    assert "rule:office_spawn_shell" in names
    assert "rule:encoded_powershell" in names
    assert "rarity:process_name" in names          # powershell unseen for user
    techs = {t.technique_id for t in det.mitre}
    assert "T1059.001" in techs and "T1027" in techs
    # every point of the score is attributable
    assert abs(det.score - min(100.0, sum(s.contribution for s in det.signals))) < 0.01


def test_false_positive_normal_browser_launch(monkeypatch):
    """explorer.exe -> chrome.exe that the user does all day -> no detection."""
    def fake_baseline(etype, eid, feature):
        if feature == "process_name":
            return _common_baseline({"chrome.exe": 900, "explorer.exe": 100})
        if feature == "parent_child":
            return _common_baseline({"explorer.exe->chrome.exe": 800})
        return _common_baseline({"x": 1000})
    monkeypatch.setattr(scorer, "get_baseline", fake_baseline)

    data = {
        "UtcTime": "2026-06-08 11:00:00",
        "Image": r"C:\...\chrome.exe",
        "CommandLine": "chrome.exe --restore",
        "ParentImage": r"C:\...\explorer.exe",
        "User": "ACME\\jdoe",
    }
    ev = sysmon.event_from_fields(1, data, {"Computer": "WS-07"})
    det = scorer.score_event(ev)
    assert det is None   # common behavior, no rules -> not flagged
