"""Detection quality harness — produces the numbers worth putting on a resume.

Runs FULLY in-memory (no DB needed):
  1. Build behavioral baselines from a benign telemetry directory.
  2. For each attack file, score its events; the file counts as DETECTED if any
     event produces a detection at/above the chosen severity.
  3. Compute true-positive rate (per attack file) and the false-positive rate
     (flagged events per 1,000) over the benign corpus.

Usage:
  python scripts/metrics.py --benign data/samples/normal \
                            --attack /path/to/EVTX-ATTACK-SAMPLES \
                            --min-severity high

The attack dir is walked recursively; technique IDs (T####[.###]) found in the
file path are used to break the TPR down per technique.
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sys
from collections import defaultdict

# make backend importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.baseline.features import extract            # noqa: E402
from app.detect.scorer import score_event            # noqa: E402
from app.ingest.parsers import generic, sysmon       # noqa: E402

SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def parse_file(path: str):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".evtx":
        yield from sysmon.parse_evtx_file(path)
    elif ext in (".json", ".ndjson"):
        yield from generic.parse_json_file(path)
    elif ext == ".csv":
        yield from generic.parse_csv_file(path)


def build_inmemory_baseline(benign_dir: str):
    hist: dict[tuple, dict] = defaultdict(lambda: defaultdict(int))
    for path in _walk(benign_dir):
        for ev in parse_file(path):
            for o in extract(ev):
                hist[(o.entity_type, o.entity_id, o.feature)][o.value] += 1

    store = {k: {"distribution": dict(v), "sample_count": sum(v.values())} for k, v in hist.items()}

    def baseline_fn(etype, eid, feature):
        return store.get((etype, eid, feature))

    return baseline_fn, len(store)


def _walk(root: str):
    for ext in ("*.evtx", "*.json", "*.ndjson", "*.csv"):
        yield from glob.glob(os.path.join(root, "**", ext), recursive=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", required=True)
    ap.add_argument("--attack", required=True)
    ap.add_argument("--min-severity", default="high", choices=list(SEV_RANK))
    args = ap.parse_args()

    baseline_fn, n_baselines = build_inmemory_baseline(args.benign)
    print(f"[*] Built {n_baselines} in-memory baselines from {args.benign}")

    floor = SEV_RANK[args.min_severity]

    # --- attack: per-file TPR ---
    attack_files = list(_walk(args.attack))
    detected = 0
    per_tech: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # tech -> [detected, total]
    for path in attack_files:
        techs = set(TECH_RE.findall(path)) or {"UNLABELED"}
        flagged = False
        for ev in parse_file(path):
            det = score_event(ev, baseline_fn)
            if det and SEV_RANK[det.severity] >= floor:
                flagged = True
                break
        detected += int(flagged)
        for t in techs:
            per_tech[t][1] += 1
            per_tech[t][0] += int(flagged)

    tpr = detected / len(attack_files) if attack_files else 0.0

    # --- benign: false-positive rate ---
    total_events = 0
    fp_events = 0
    for path in _walk(args.benign):
        for ev in parse_file(path):
            total_events += 1
            det = score_event(ev, baseline_fn)
            if det and SEV_RANK[det.severity] >= floor:
                fp_events += 1
    fp_per_1k = (fp_events / total_events * 1000) if total_events else 0.0

    print("\n================ SOC PARALLAX — detection metrics ================")
    print(f"min severity counted as a hit : {args.min_severity}")
    print(f"attack files                  : {len(attack_files)}")
    print(f"attack files detected         : {detected}")
    print(f"TRUE POSITIVE RATE            : {tpr:.1%}")
    print(f"benign events evaluated       : {total_events}")
    print(f"false positives               : {fp_events}")
    print(f"FALSE POSITIVES / 1k EVENTS   : {fp_per_1k:.2f}")
    print("------------------------------------------------------------------")
    print("per-technique detection:")
    for tech, (d, tot) in sorted(per_tech.items()):
        print(f"  {tech:12s} {d}/{tot}")
    print("==================================================================")
    print("\nResume line:")
    print(f'  "Detected {detected}/{len(attack_files)} ATT&CK techniques from real '
          f'EVTX attack telemetry at {tpr:.0%} TPR, {fp_per_1k:.1f} FP/1k events."')


if __name__ == "__main__":
    main()
