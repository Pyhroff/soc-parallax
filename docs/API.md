# API Reference

Base URL: `http://localhost:8000` · Interactive docs: `/docs` (Swagger).

## Authentication
Every endpoint except `GET /health` needs an `X-API-Key` header. Three keys exist, set through the
environment (`API_KEY_ANALYST`, `API_KEY_INGEST`, `API_KEY_ADMIN`). With no keys configured the API
answers 401 to everything unless `AUTH_DISABLED=true` is set for local development.

| Role | Can |
|------|-----|
| analyst | all GET endpoints, `/investigate` |
| ingest | analyst + `/ingest/*` (except `/ingest/pipeline`), `/detect/run`, `/correlate/run` |
| admin | everything, including `/baseline/build` and `/ingest/pipeline` |

File ingestion paths are relative to `INGEST_ROOT`; `..`, absolute paths and symlinks that leave it are rejected (400).
Limits: `MAX_INGEST_FILE_BYTES`, `MAX_INGEST_FILES`, `MAX_RECORDS_PER_REQUEST`.

## Meta
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness only (no auth, no dependency details) |
| GET | `/health/deps` | Postgres and Neo4j status (analyst) |

## Ingest
| Method | Path | Body | Description |
|--------|------|------|-------------|
| POST | `/ingest/file` | `{"path": "...", "dataset": "baseline\|observed"}` | Ingest one .evtx/.json/.csv file |
| POST | `/ingest/dir` | `{"path": "...", "dataset": "baseline\|observed"}` | Recursively ingest a directory |
| POST | `/ingest/records` | `[ {...}, ... ]` | Ingest live JSON records (also writes graph) |
| POST | `/ingest/pipeline` | `{"path":"...","train":false}` | Ingest (observed) → optional baseline build from `baseline` data → detect → correlate |

## Baselines
| Method | Path | Description |
|--------|------|-------------|
| POST | `/baseline/build` | Rebuild baselines over the training window (`{"days": 30}`) |
| GET | `/baseline?entity_type=&entity_id=&feature=` | Inspect one baseline histogram |

## Detections
| Method | Path | Description |
|--------|------|-------------|
| POST | `/detect/run` | Score all un-scored events (`{"min_severity":"low"}`) |
| GET | `/detections?severity=&limit=` | List detections (with attributable signals) |

## Incidents
| Method | Path | Description |
|--------|------|-------------|
| POST | `/correlate/run` | Group detections into incidents + generate narratives |
| GET | `/incidents?status=&limit=` | List incidents |
| GET | `/incidents/{id}` | Full incident: detections, narrative, subgraph, similar incidents |

## Investigation / Graph / Prediction
| Method | Path | Description |
|--------|------|-------------|
| POST | `/investigate` | `{"entity_type","entity_id","window_hours"}` → workflow steps + narrative |
| GET | `/graph/blast-radius?entity=` | Hosts the user logged into and IPs contacted from those hosts (host exposure, not attribution) |
| GET | `/predict/next?technique_id=` | Likely next techniques (from PRECEDES edges) |
| GET | `/overview` | Dashboard rollup stats |

## Detection object (shape)
```json
{
  "detection_id": "uuid",
  "entity_type": "user",
  "entity_id": "ACME\\jdoe",
  "score": 100.0,
  "severity": "critical",
  "signals": [
    {"name": "rule:office_spawn_shell", "weight": 0.5, "sub_score": 0.9,
     "contribution": 45.0, "evidence": "winword.exe spawned powershell.exe …",
     "mitre": [{"technique_id": "T1566", "tactic": "Initial Access", "name": "Phishing"}]}
  ],
  "mitre": [ ... ]
}
```
