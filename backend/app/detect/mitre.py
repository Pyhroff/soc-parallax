"""Load the MITRE rulebook and resolve signal names -> MitreRef list."""
from __future__ import annotations

import functools
import os

import yaml

from app.schemas.detection import MitreRef

_RULEBOOK_PATH = os.path.join(os.path.dirname(__file__), "mitre.yaml")


@functools.lru_cache(maxsize=1)
def _rulebook() -> dict:
    with open(_RULEBOOK_PATH, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def techniques_for(signal_name: str) -> list[MitreRef]:
    book = _rulebook()
    catalog = book["techniques"]
    refs: list[MitreRef] = []
    for tid in book["signal_map"].get(signal_name, []):
        meta = catalog.get(tid, {})
        refs.append(MitreRef(technique_id=tid, tactic=meta.get("tactic", "Unknown"),
                             name=meta.get("name", tid)))
    return refs


def all_technique_ids() -> set[str]:
    return set(_rulebook()["techniques"].keys())
