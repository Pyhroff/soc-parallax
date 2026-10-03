"""Detection evaluation harness (in-memory, no database).

What it measures, and why it is split this way:

  * Baselines are trained ONLY on --train (benign), and events that already trip
    a contextual rule are excluded from training so attacker behavior cannot
    teach the baseline that it is normal.
  * False positives are measured on data the baseline never saw:
      --heldout-known   later benign activity from the SAME users/hosts (time-disjoint)
      --heldout-unseen  benign activity from entities with NO history (entity-disjoint)
    Measuring on the training set (the old behavior) cannot show a false positive.
  * True positives use real attack .evtx files. Each is scored two ways:
      rules-only  contextual rules, no baseline (what generalizes to a new environment)
      full        rules plus rarity signals from the benign baseline
    Files that parse to zero events are counted and reported, not hidden.
  * The per-tactic breakdown comes from the corpus's top-level folder names.

Usage:
  python scripts/generate_demo_data.py
  python scripts/metrics.py --train data/samples/normal/baseline_normal.json \
      --heldout-known data/samples/normal/heldout_known.json \
      --heldout-unseen data/samples/normal/heldout_unseen.json \
      --attack /path/to/EVTX-ATTACK-SAMPLES --json out.json
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.baseline.features import extract            # noqa: E402
from app.detect import scorer                        # noqa: E402
from app.detect.signals import rules                 # noqa: E402
from app.ingest.parsers import generic, sysmon       # noqa: E402

SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def parse_file(path: str):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".evtx":
        yield from sysmon.parse_evtx_file(path)
    elif ext in (".json", ".ndjson"):
        yield from generic.parse_json_file(path)
    elif ext == ".csv":
        yield from generic.parse_csv_file(path)


def _files(root: str, exts: tuple[str, ...]):
    if os.path.isfile(root):
        return [root]
    out = []
    for e in exts:
        out += glob.glob(os.path.join(root, "**", f"*{e}"), recursive=True)
    return sorted(out)


def build_baseline(train_path: str):
    hist: dict[tuple, dict] = defaultdict(lambda: defaultdict(int))
    used = skipped = 0
    for path in _files(train_path, (".json", ".ndjson", ".csv", ".evtx")):
        for ev in parse_file(path):
            if rules.evaluate(ev):
                skipped += 1               # never train on rule-matching behavior
                continue
            used += 1
            for o in extract(ev):
                hist[(o.entity_type, o.entity_id, o.feature)][o.value] += 1
    store = {k: {"distribution": dict(v), "sample_count": sum(v.values())} for k, v in hist.items()}
    return (lambda t, e, f: store.get((t, e, f))), {"train_events": used, "train_skipped_rule_hits": skipped,
                                                    "baselines": len(store)}


def false_positives(path: str, baseline_fn, floor: int) -> dict:
    total = fp = 0
    for p in _files(path, (".json", ".ndjson", ".csv")):
        for ev in parse_file(p):
            total += 1
            det = scorer.score_event(ev, baseline_fn)
            fp += int(bool(det and SEV_RANK[det.severity] >= floor))
    return {"events": total, "false_positives": fp, "per_1k": round(fp / total * 1000, 2) if total else 0.0}


def attack_eval(root: str, baseline_fn, floor: int) -> dict:
    files = _files(root, (".evtx",))
    res = {"files": len(files), "zero_events": 0, "rules_any": 0, "full_at_floor": 0, "rules_at_floor": 0}
    tactics: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])   # total, rules_any, full
    for path in files:
        rel = os.path.relpath(path, root)
        tactic = rel.split(os.sep)[0] if os.sep in rel else "unlabeled"
        n = rules_any = rules_floor = full_floor = 0
        for ev in parse_file(path):
            n += 1
            rules_any = rules_any or bool(rules.evaluate(ev))
            d0 = scorer.score_event(ev, lambda *_: None)
            rules_floor = rules_floor or bool(d0 and SEV_RANK[d0.severity] >= floor)
            d1 = scorer.score_event(ev, baseline_fn)
            full_floor = full_floor or bool(d1 and SEV_RANK[d1.severity] >= floor)
        res["zero_events"] += int(n == 0)
        res["rules_any"] += int(rules_any)
        res["rules_at_floor"] += int(rules_floor)
        res["full_at_floor"] += int(full_floor)
        t = tactics[tactic]
        t[0] += 1
        t[1] += int(rules_any)
        t[2] += int(full_floor)
    res["by_tactic"] = {k: {"files": v[0], "rules_any": v[1], "full_at_floor": v[2]}
                        for k, v in sorted(tactics.items())}
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--heldout-known")
    ap.add_argument("--heldout-unseen")
    ap.add_argument("--attack")
    ap.add_argument("--min-severity", default="high", choices=list(SEV_RANK))
    ap.add_argument("--json", dest="json_out")
    a = ap.parse_args()
    floor = SEV_RANK[a.min_severity]

    baseline_fn, info = build_baseline(a.train)
    out: dict = {"min_severity": a.min_severity, "training": info}
    if a.heldout_known:
        out["benign_known_entities"] = false_positives(a.heldout_known, baseline_fn, floor)
    if a.heldout_unseen:
        out["benign_unseen_entities"] = false_positives(a.heldout_unseen, baseline_fn, floor)
    if a.attack:
        out["attack"] = attack_eval(a.attack, baseline_fn, floor)

    print(json.dumps(out, indent=2))
    if a.json_out:
        with open(a.json_out, "w") as fh:
            json.dump(out, fh, indent=2)


if __name__ == "__main__":
    main()
