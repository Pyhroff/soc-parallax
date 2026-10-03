# Detection Logic & MITRE Coverage

Every detection is explainable and maps to MITRE ATT&CK where a mapping is justified.
`score = min(100, Σ contribution)`, where `contribution = weight × sub_score × 100`.
Measured performance and its limits: [`EVALUATION.md`](EVALUATION.md).

## Scoring model

### 1. Contextual rules (high fidelity, no baseline needed)
Weight `0.50`. Defined in `app/detect/signals/rules.py`, mapped to ATT&CK in `app/detect/mitre.yaml`.
Command lines are tokenized, so `-enc`, `-e`, `-ec`, `-EncodedCommand` and other accepted prefixes are all recognized.
The binary identity is the PE `OriginalFileName` when present, so renaming a binary does not hide it.

| Rule | sub_score | MITRE | Fires when |
|------|-----------|-------|------------|
| `office_spawn_shell` | 0.90 | T1566, T1059.001 | Office app launches a shell or LOLBIN |
| `encoded_powershell` | 0.85 | T1059.001, T1027 | PowerShell with an encoded-command flag and a payload |
| `cmd_download` | 0.75 | T1105 | Download cradle (DownloadString, iwr, certutil -urlcache, ...) |
| `lolbin_execution` | 0.60 | T1218 | rundll32 / regsvr32 / mshta / certutil / bitsadmin / msbuild / installutil with suspicious arguments, or an office/script-host parent. `msbuild` from a developer tool is exempt |
| `suspicious_parent` | 0.70 | T1055, T1036 | Server process (w3wp, sqlservr, wmiprvse, ...) spawns a shell |
| `credential_tool` | 0.90 | T1003 | mimikatz, or arguments such as sekurlsa, lsadump::, comsvcs minidump, procdump on lsass |
| `scheduled_task` | 0.60 | T1053 | schtasks /create |
| `remote_exec` | 0.70 | T1021 | psexec family, or wmic /node ... process call create |
| `autostart_registry` | 0.65 | T1547 | Run / RunOnce key write |
| `renamed_binary` | 0.70 | T1036.003 | PE original filename differs from the image name |
| `system_binary_wrong_path` | 0.80 | T1036.005 | svchost/lsass/csrss/... running outside System32 |

A single rule contributes at most 45 points, so one rule alone lands at low or medium severity; stacked
rules or a rarity signal on top are needed to reach high.

### 2. Rarity signals (need history)
`sub_score = min(1, -log(p) / 3.3)` with `p` the Laplace-smoothed probability of the value for that entity/feature.

| Feature | Entity | Weight |
|---------|--------|--------|
| `process_name` | user | 0.35 |
| `parent_child` | host | 0.30 |
| `login_hour` | user | 0.20 |
| `src_ip` | user | 0.20 |
| `dest_ip` | host | 0.20 |
| `domain` | host | 0.15 |

Calibration rules, each added because the opposite was measured to be wrong:

- No rarity signal unless the baseline has at least `MIN_BASELINE_SAMPLES` (50) observations. A new
  user or host is not flagged for being new.
- Each feature counts once per event (the stronger of the entity baselines), not once per entity.
- Rarity below 0.55 is ignored.
- Rarity signals carry no ATT&CK technique: unusual is not a technique.
- A detection with no rule behind it is capped at `RARITY_ONLY_CAP` (69), so rarity alone is never high or critical.
- Baselines are trained only from events labelled `baseline`, and events that trip a rule are excluded.

## Severity thresholds
`low < 40 ≤ medium < 70 ≤ high < 90 ≤ critical` (tunable in `config.py`).

## Worked example
`winword.exe → powershell.exe -enc …` for a user with an established baseline who never runs PowerShell:

| Signal | contribution |
|--------|-------------|
| rule:office_spawn_shell | 45.0 |
| rule:encoded_powershell | 42.5 |
| rarity:process_name | up to 35 |
| **score** | **100 (critical)** |

Each line is reconstructable from `detection.signals`.

## Known weaknesses
- Rules are string and field matches on process creation events; an attacker who avoids the matched patterns is not caught.
- Rarity flags rare-but-normal behavior at medium severity; this is why it is capped.
- Histogram baselines lose sequence and timing information.
- Only Sysmon and Security-Auditing EVTX events are parsed; other providers are skipped.
