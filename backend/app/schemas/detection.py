"""Detection / incident output schemas."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class MitreRef(BaseModel):
    technique_id: str          # e.g. T1059.001
    tactic: str                # e.g. Execution
    name: str                  # e.g. PowerShell


class Signal(BaseModel):
    """One contributing reason a detection fired. Every point of the score is
    attributable to a signal — this is the explainability contract."""
    name: str                  # e.g. rarity:process_name
    weight: float              # configured importance 0..1
    sub_score: float           # this signal's raw anomaly strength 0..1
    contribution: float        # weight * sub_score, in final score points
    evidence: str              # human-readable justification
    mitre: list[MitreRef] = Field(default_factory=list)


class Detection(BaseModel):
    detection_id: UUID | None = None
    event_id: UUID
    entity_type: str           # user | host | process
    entity_id: str
    score: float               # 0..100
    severity: str              # low | medium | high | critical
    signals: list[Signal]
    mitre: list[MitreRef]
    created_at: datetime | None = None


class Incident(BaseModel):
    incident_id: UUID | None = None
    title: str
    status: str = "open"
    severity: str
    entity_type: str | None = None
    entity_id: str | None = None
    detection_ids: list[UUID] = Field(default_factory=list)
    narrative: str | None = None
    mitre_chain: list[MitreRef] = Field(default_factory=list)
    created_at: datetime | None = None
