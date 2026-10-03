"""Anti-hallucination guard.

A narrative may only contain facts that are in the evidence bundle. After
generation we normalize the text (so `1[.]2[.]3[.]4`, `T 1003`, hex IPs and
IPv6 cannot slip past), then verify:

  * every IP address and MITRE technique id exists in the evidence
  * every hostname / DOMAIN\\user looking token exists in the evidence
  * every multi-digit number exists in the evidence
  * severe claim words (ransomware, exfiltration, ...) appear only if the
    evidence itself contains them

This is a consistency check against the evidence, not a proof of truth: the
evidence is itself derived from attacker-controllable logs, which narrator.py
treats as untrusted data.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

IP4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IP6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
HEX_IP_RE = re.compile(r"\b0x[0-9a-fA-F]{8}\b")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
NUM_RE = re.compile(r"(?<![\w.])\d{2,}(?![\w.])")
HOST_RE = re.compile(r"\b[A-Za-z]{2,}[-_]\d+\b|\b[A-Za-z]{2,}\d{2,}\b")
ACCOUNT_RE = re.compile(r"\b[\w.-]+\\[\w.$-]+")

CLAIM_WORDS = (
    "ransomware", "exfiltrat", "data breach", "nation-state", "nation state", "apt",
    "domain admin", "zero-day", "zero day", "botnet", "backdoor", "wiper", "extortion",
)


@dataclass
class GroundingResult:
    ok: bool
    violations: list[str]


def normalize(text: str) -> str:
    t = text
    t = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", ".", t, flags=re.I)
    t = re.sub(r"\[\s*:\s*\]", ":", t)
    t = re.sub(r"\bhxxp", "http", t, flags=re.I)
    t = re.sub(r"\bT[\s\-_]*(\d{4})(?:[\s.]*(\d{3}))?\b",
               lambda m: f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else ""), t, flags=re.I)
    t = re.sub(r"\bt(\d{4}(?:\.\d{3})?)\b", r"T\1", t)
    return t


def _ips(text: str) -> set[str]:
    found: set[str] = set()
    for m in IP4_RE.findall(text):
        try:
            found.add(str(ipaddress.IPv4Address(m)))
        except ValueError:
            found.add(m)                 # malformed -> keep raw so it fails the allowlist
    for m in HEX_IP_RE.findall(text):
        found.add(str(ipaddress.IPv4Address(int(m, 16))))
    for m in IP6_RE.findall(text):
        try:
            found.add(ipaddress.IPv6Address(m).compressed)
        except ValueError:
            continue
    return found


def facts_in(text: str) -> dict[str, set[str]]:
    n = normalize(text)
    return {
        "ips": _ips(n),
        "techs": set(TECH_RE.findall(n)),
        "nums": set(NUM_RE.findall(IP4_RE.sub(" ", TECH_RE.sub(" ", n)))),
        "entities": {h.lower() for h in HOST_RE.findall(n)} | {a.lower() for a in ACCOUNT_RE.findall(n)},
    }


def check(narrative: str, evidence: str, allowed_techniques: set[str] | None = None) -> GroundingResult:
    """Verify `narrative` against the raw `evidence` text it was generated from."""
    ev, nar = facts_in(evidence), facts_in(narrative)
    allowed_techs = ev["techs"] | (allowed_techniques or set())
    violations: list[str] = []
    violations += [f"ungrounded IP: {i}" for i in sorted(nar["ips"] - ev["ips"])]
    violations += [f"ungrounded technique: {t}" for t in sorted(nar["techs"] - allowed_techs)]
    violations += [f"ungrounded entity: {e}" for e in sorted(nar["entities"] - ev["entities"])]
    violations += [f"ungrounded number: {x}" for x in sorted(nar["nums"] - ev["nums"])]
    low_nar, low_ev = narrative.lower(), evidence.lower()
    for w in CLAIM_WORDS:
        if w in low_nar and w not in low_ev:
            violations.append(f"unsupported claim: '{w}'")
    return GroundingResult(ok=not violations, violations=violations)
