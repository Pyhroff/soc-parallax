# Detection Logic & MITRE Coverage

This is the document an interviewer will drill into. Every detection here is
explainable and maps to MITRE ATT&CK. Scores are attributable — `score =
min(100, Σ contribution)`, where `contribution = weight × sub_score × 100`.

## Scoring model

Two signal families combine into one detection:

### 1. Rarity signals (need a behavioral baseline)
`sub_score = min(1, -log(p) / 3.3)` where `p` is the Laplace-smoothed probability
of the observed value for that entity/feature. A never-before-seen value → high
sub_score. Smoothing keeps it finite and avoids divide-by-zero on cold start.

| Feature | Entity | Weight | Behavioral question |
|---------|--------|--------|---------------------|
| `process_name` | user | 0.35 | Does this user normally run this program? |
| `parent_child` | host | 0.30 | Is this parent→child process chain normal here? |
| `login_hour`   | user | 0.20 | Does this user normally log in at this hour? |
| `src_ip`       | user | 0.20 | Does this user normally log in from this IP? |
| `dest_ip`      | host | 0.20 | Does this host normally talk to this IP? |
| `domain`       | host | 0.15 | Does this host normally resolve this domain? |

Rarity below `0.55` is ignored (not anomalous enough → controls false positives).

### 2. Contextual rules (no baseline needed — suspicious regardless of history)
Weight `0.50`, sub_score per rule. Defined in `app/detect/signals/rules.py`,
mapped to ATT&CK in `app/detect/mitre.yaml`.

| Rule | sub_score | MITRE | Rationale |
|------|-----------|-------|-----------|
| `office_spawn_shell` | 0.90 | T1566, T1059.001 | Word/Excel spawning a shell = phishing payload |
| `encoded_powershell` | 0.85 | T1059.001, T1027 | `-enc` base64 command = obfuscated execution |
| `cmd_download` | 0.75 | T1105 | Download cradle (IEX/WebClient/certutil) |
| `lolbin_execution` | 0.60 | T1218 | rundll32/regsvr32/mshta/certutil abuse |
| `suspicious_parent` | 0.70 | T1055, T1036 | service→shell chain (e.g. w3wp→cmd) |
| `credential_tool` | 0.90 | T1003 | mimikatz/procdump/sekurlsa |
| `scheduled_task` | 0.60 | T1053 | schtasks /create persistence |
| `remote_exec` | 0.70 | T1021 | psexec / wmic process call create |
| `autostart_registry` | 0.65 | T1547 | Run/RunOnce key write |

## Severity thresholds
`low < 40 ≤ medium < 70 ≤ high < 90 ≤ critical` (tunable in `config.py`).

## Worked example — the phishing scenario
`winword.exe → powershell.exe -enc …` at 02:14 for a user who never runs PowerShell:

| Signal | contribution |
|--------|-------------|
| rule:office_spawn_shell | 45.0 |
| rule:encoded_powershell | 42.5 |
| rarity:process_name (powershell unseen for jdoe) | ~31 |
| **score** | **100 (critical)** |

Each line is reconstructable from `detection.signals` — that's the whole point.

## Known weaknesses (have an honest answer ready)
- **Cold start**: a brand-new entity has no baseline; rarity is suppressed (returns
  a low constant) so new users aren't auto-flagged. Trade-off: misses true positives
  during the learning window.
- **Rare-but-legit**: a sysadmin's first-ever use of a tool can false-positive. Mitigation
  path: per-role allowlists / suppression rules / analyst feedback loop (roadmap).
- **Encoding the baseline as histograms** loses sequence/timing info — good enough for
  v1, but sequence models (n-gram / HMM) are the natural next step.
