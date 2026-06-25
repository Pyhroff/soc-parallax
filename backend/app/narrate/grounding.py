"""Anti-hallucination guard.

A narrative may only reference facts present in the evidence bundle. After
generation we extract every IP and MITRE technique id from the text and verify
each one exists in the evidence. If not, the narrative is rejected.

This test is the difference between 'I bolted an LLM onto my logs' and a tool a
SOC would trust.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


@dataclass
class GroundingResult:
    ok: bool
    violations: list[str]


def check(narrative: str, allowed_ips: set[str], allowed_techniques: set[str]) -> GroundingResult:
    violations: list[str] = []
    for ip in set(IP_RE.findall(narrative)):
        if ip not in allowed_ips:
            violations.append(f"ungrounded IP: {ip}")
    for tech in set(TECH_RE.findall(narrative)):
        if tech not in allowed_techniques:
            violations.append(f"ungrounded technique: {tech}")
    return GroundingResult(ok=not violations, violations=violations)
