# API Reference

Base URL: `http://localhost:8000` · Interactive docs: `/docs` (Swagger).

## Meta
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | App + Postgres + Neo4j health |

## Ingest
| Method | Path | Body | Description |
|--------|------|------|-------------|
| POST | `/ingest/file` | `{"path": "..."}` | Ingest one .evtx/.json/.csv file |
| POST | `/ingest/dir` | `{"path": "..."}` | Recursively ingest a directory |
| POST | `/ingest/records` | `[ {...}, ... ]` | Ingest live JSON records (also writes graph) |
| POST | `/ingest/pipeline` | `{"path":"...","train":true}` | Ingest → baseline → detect → correlate |

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
| POST | `/investigate` | `{"entity_type","entity_id","window_hours"}` → agent steps + narrative |
| GET | `/graph/blast-radius?entity=` | Hosts touched + external IPs contacted |
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
