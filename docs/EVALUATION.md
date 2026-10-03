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

The attack files are split deterministically (by file-name hash) into a dev half (150) and a test half (128).
Rule weights were calibrated on the dev half only; the test half was scored once with the final settings.
Caveat: I read the provider and event-ID mix of the whole corpus (both halves) while deciding which parsers to
write, so the test half is a cleaner estimate than the full set but not a fully blind one.

| Measure | Dev (150) | Test (128) | All (278) |
|---|---|---|---|
| Files that parse to zero events | 28 | 18 | 46 (16.5%) |
| At least one rule fires, any severity | 55 (36.7%) | 45 (35.2%) | 100 (36.0%) |
| Detection at severity medium or higher | 47 (31.3%) | 35 (27.3%) | 82 (29.5%) |
| Detection at severity high or higher | | | 5 (1.8%) |

Benign data (synthetic, never seen by the baseline):

| Measure | Result |
|---|---|
| Known entities, later weeks, severity high or higher | 0 / 1,773 events |
| Known entities, severity medium or higher | 16 / 1,773 (9.0 per 1,000), all rarity-only |
| Unseen entities, severity medium or higher | 0 / 1,011 events |

How the numbers moved: the first honest run (rules only, Sysmon and 4688 parsing) gave 19.8% any-rule and 1.8%
at medium or higher. Adding parsers and rules for PowerShell 4104 script blocks, scheduled tasks (4698),
service installs (7045), Sysmon process access and remote threads, DCSync (4662), admin-share writes (5145) and
log clearing (1102) took any-rule to 36.0%, and raising the contextual-rule weight from 0.5 to 0.6 (chosen on the
dev half) let single strong rules reach medium. The medium-or-higher benign false-positive count did not change.

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

- The benign data is synthetic and small. Zero false positives at high severity says the rules are not trivially noisy,
  not that they are quiet on a real network. Rarity-only alerts fire on rare-but-normal behavior (9 per 1,000
  known-entity events here), which is why rarity alone is capped at medium.
- Real benign logs are supported but not yet in the published numbers: `--benign-evtx DIR` trains on the first 70%
  (by time) of real goodware logs and measures false positives on the last 30%. Good sources are your own machine
  (`scripts/export_local_logs.ps1`) and the goodware EVTX releases of NextronSystems/evtx-baseline. I could not download
  the latter from the environment this was built in, so that run is still to do.
- The attack corpus is single-technique lab telemetry, not intrusions, and a file counts as detected if any one event fires.
- 46 files (16.5%) still parse to zero events: Windows Firewall/RPC/BITS/RDP/Defender and legacy PowerShell 800
  records, plus several Security events (4663, 4799) without rules. These are the next parsers to add.
- Rules were written knowing the corpus's categories, so even the test half overstates performance on unseen attacks.

## Reproduce

```bash
python scripts/generate_demo_data.py
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES data/external/evtx
python scripts/metrics.py --train data/samples/normal/baseline_normal.json \
  --heldout-known data/samples/normal/heldout_known.json \
  --heldout-unseen data/samples/normal/heldout_unseen.json \
  --attack data/external/evtx --min-severity medium --json eval.json
```
