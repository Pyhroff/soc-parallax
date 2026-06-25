"""Build the evidence bundle, prompt the LLM, and enforce grounding."""
from __future__ import annotations

from app.narrate import grounding
from app.narrate.llm import EchoProvider, get_provider
from app.schemas.detection import Detection

SYSTEM_PROMPT = (
    "You are a senior SOC analyst writing an incident note. You explain WHY the "
    "supplied evidence is suspicious, in 2-3 short paragraphs, professional tone. "
    "STRICT RULES: Use ONLY the facts in the evidence below. Do not invent IP "
    "addresses, hostnames, usernames, or MITRE technique IDs. Do not speculate "
    "beyond the evidence. End with one concrete recommended next step."
)


def _evidence_text(det: Detection) -> str:
    lines = [
        f"Entity: {det.entity_type} '{det.entity_id}'",
        f"Risk score: {det.score}/100 ({det.severity})",
        "Signals that fired (each is a reason this was flagged):",
    ]
    for s in det.signals:
        techs = ", ".join(t.technique_id for t in s.mitre) or "-"
        lines.append(f"  - [{s.contribution} pts] {s.evidence}  (MITRE: {techs})")
    techniques = sorted({t.technique_id + " " + t.name for t in det.mitre})
    lines.append("Mapped MITRE techniques: " + ("; ".join(techniques) or "none"))
    return "\n".join(lines)


def _allowed_facts(det: Detection) -> tuple[set[str], set[str]]:
    ips: set[str] = set()
    for s in det.signals:
        for token in s.evidence.replace("'", " ").split():
            if token.count(".") == 3 and all(p.isdigit() for p in token.split(".")):
                ips.add(token)
    techs = {t.technique_id for t in det.mitre}
    return ips, techs


def narrate(det: Detection, max_retries: int = 2) -> tuple[str, grounding.GroundingResult]:
    evidence = _evidence_text(det)
    allowed_ips, allowed_techs = _allowed_facts(det)
    provider = get_provider()

    prompt = f"EVIDENCE:\n{evidence}\n\nWrite the analyst note now."
    result = grounding.GroundingResult(ok=False, violations=["not generated"])
    narrative = ""

    for _ in range(max_retries + 1):
        narrative = provider.generate(SYSTEM_PROMPT, prompt)
        result = grounding.check(narrative, allowed_ips, allowed_techs)
        if result.ok:
            return narrative, result
        # tighten the instruction and retry
        prompt = (
            f"EVIDENCE:\n{evidence}\n\nYour previous answer referenced facts not in "
            f"the evidence ({'; '.join(result.violations)}). Rewrite using ONLY the "
            f"evidence above."
        )

    # Grounding failed after retries -> fall back to a deterministic, grounded summary.
    fallback = _deterministic_narrative(det)
    return fallback, grounding.check(fallback, allowed_ips, allowed_techs)


def _deterministic_narrative(det: Detection) -> str:
    reasons = " ".join(f"{s.evidence}." for s in det.signals[:4])
    techs = ", ".join(sorted({t.technique_id for t in det.mitre}))
    return (
        f"This {det.severity}-severity activity for {det.entity_type} "
        f"'{det.entity_id}' scored {det.score}/100. {reasons} "
        f"Together these behaviors map to MITRE techniques {techs} and resemble "
        f"post-compromise activity. Recommended next step: triage the affected "
        f"entity and review surrounding events on the same host."
    )
