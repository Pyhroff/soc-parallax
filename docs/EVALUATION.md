# Evaluation

How detection quality is measured here, what the numbers are, and what they do not show.
Reproduce with `scripts/metrics.py` (see the bottom of this page). Everything below was
produced by that script; the `evaluation` GitHub Actions workflow re-runs it on demand.

## Method

- Baselines are trained only on `baseline_normal.json` (synthetic, 8 weeks, 6 users on 6 hosts with
  different profiles). Events that already trip a contextual rule are excluded from training.
- False positives are measured on data the baseline never saw, in two ways:
  `heldout_known.json` (the following 2 weeks, same users: time-disjoint) and
  `heldout_unseen.json` (3 users and hosts with no history: entity-disjoint, the new-hire case).
  Both deliberately include benign activity that looks like tradecraft (msbuild launched from Visual
  Studio, `certutil -hashfile`, `schtasks /query`, `powershell -File`).
- True positives use the 278 `.evtx` files of the public EVTX-ATTACK-SAMPLES corpus. A file counts as
  detected if any of its events produces a detection. Each file is scored two ways: rules only (no
  baseline, which is what generalizes to a new environment) and rules plus the benign baseline.
- Files that parse to zero events are counted and reported, not dropped.

## Results (seed 1337, corpus snapshot of 278 files)

| Measure | Result |
|---|---|
| Attack files | 278 |
| Files that parse to zero events | 76 (27%): logs from providers the parser does not read yet |
| Files where at least one rule fires (any severity) | 55 / 278 (19.8%); 55 / 202 of parseable files (27.2%) |
| Files with a detection at severity medium or higher | 5 / 278 (1.8%) |
| Files with a detection at severity high or higher | 3 / 278 (1.1%) |
| Benign, known entities, severity high or higher | 0 / 1,773 events |
| Benign, known entities, severity medium or higher | 16 / 1,773 (9.0 per 1,000) |
| Benign, unseen entities, severity medium or higher | 0 / 1,011 events |

Per tactic, files where a rule fires: Execution 9/34, Lateral Movement 10/47, Privilege Escalation 10/66,
Defense Evasion 8/36, Credential Access 5/39, Persistence 4/22, Discovery 0/11, Command and Control 0/6.

## What changed from the earlier published numbers, and why

The earlier README reported 53% true positives and 0.0 false positives per 1,000 events. Both were wrong
in a way that the harness could not reveal:

- Of the 147 files that counted as detected, 107 were detected only because a new entity with no baseline
  scored as maximally surprising (a "cold start" artifact), and only 39 involved a rule. Rules alone fired on
  15.8% of files at the time.
- 135 of 156 benign events from an unseen user scored critical. A new hire's first Chrome launch scored 90.77.
- The 0.0 false positive rate was measured on the same 520 synthetic events the baseline had been trained on,
  all from one user on one host, so it could not have been anything else.

The scorer now emits no rarity signal without at least `MIN_BASELINE_SAMPLES` (50) observations, counts each
feature once, caps rarity-only detections at 69 (medium), and attaches no ATT&CK technique to a rarity signal.
The honest TPR is lower, and that is the number to quote.

## Limits that remain

- The benign data is synthetic and small. Zero false positives on it says the rules are not trivially noisy,
  not that they are quiet on a real network. Medium-severity rarity alerts fire on rare-but-normal behavior
  (9 per 1,000 known-entity events here), which is why rarity alone cannot reach high.
- The attack corpus is single-technique lab telemetry, not intrusions. A file is detected if any one event fires.
- 27% of the corpus is unparsed (PowerShell, TaskScheduler, WMI-Activity, System and other providers). Adding
  those parsers is the largest single coverage gain available.
- Rule thresholds were written before this evaluation and not tuned to it. Most single rules score below 40 and
  show up as low severity, so recall at medium or higher is far lower than recall at any severity.
- Rules were developed while looking at this corpus's categories, so treat the rules-only numbers as a
  development-set result, not a clean held-out estimate.

## Reproduce

```bash
python scripts/generate_demo_data.py
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES data/external/evtx
python scripts/metrics.py --train data/samples/normal/baseline_normal.json \
  --heldout-known data/samples/normal/heldout_known.json \
  --heldout-unseen data/samples/normal/heldout_unseen.json \
  --attack data/external/evtx --min-severity medium --json eval.json
```
