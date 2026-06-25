# SOC PARALLAX

**Cyber Behavioral Intelligence Platform** — learns per-entity behavioral
baselines, scores anomalies with a fully *attributable* risk score, maps them to
MITRE ATT&CK, correlates them into incidents in a memory graph, and explains
*why* something is suspicious in grounded, analyst-grade language.

> Not a SIEM. Not a log viewer. SOC PARALLAX answers *what is happening*,
> *what happened before*, and *what is likely to happen next* — and shows its work.

![status](https://img.shields.io/badge/status-MVP-blue) ![tests](https://img.shields.io/badge/tests-passing-brightgreen)

---

## Why this exists

Most detection demos are black boxes: "the model flagged it." SOC PARALLAX is a
**glass box** — every point of a risk score traces to a named signal, every
MITRE mapping comes from a versioned rulebook (not an LLM guess), and every
generated narrative passes an **anti-hallucination check** before it's shown.

## What's built (the vertical slice)

| Module | Status | What it does |
|--------|--------|--------------|
| Ingest pipeline | ✅ | Sysmon/EVTX, Windows Event, JSON/ECS, CSV → unified event schema |
| Behavioral DNA engine | ✅ | Per-user/host/process baselines; smoothed rarity + rule scoring |
| Detection + MITRE | ✅ | Attributable signals, YAML ATT&CK rulebook |
| Narrative intelligence | ✅ | Local LLM (Ollama) narratives with a grounding guard |
| Organizational memory graph | ✅ | Neo4j entities/edges; blast radius, campaign clustering |
| Autonomous investigation | ✅ | Deterministic LangGraph: collect→baseline→mitre→correlate→narrate |
| SOC command center | ✅ | Next.js dark UI: Overview, Incidents, Graph, Investigations, Predictions |
| Threat evolution predictor | ◑ | Seeded from graph `PRECEDES` edges (ML-ready) |

### Roadmap (designed for, not yet built)
Attack Genome similarity engine · Kafka streaming ingest · OpenSearch full-text ·
RBAC + multi-tenant · Attack Replay step-through · Kubernetes deploy. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §1 for why each is deferred.

---

## Architecture

```
Next.js UI ──REST──> FastAPI ──> PostgreSQL (events, baselines, detections, incidents)
                         │
                         ├──────> Neo4j   (memory graph)
                         └──────> Ollama  (grounded narratives)
```

Full design, schemas, and the detection math: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quickstart

```bash
# 1. bring up postgres + neo4j + ollama + backend + frontend
docker compose up --build

# 2. pull a local model for narratives (first run only)
docker exec parallax-ollama ollama pull llama3

# 3. generate the bundled demo dataset (synthetic, for smoke test)
python scripts/generate_demo_data.py

# 4. run the full pipeline: ingest -> baseline -> detect -> correlate
curl -X POST localhost:8000/ingest/pipeline \
     -H 'content-type: application/json' \
     -d '{"path":"/data/samples","train":true}'

# 5. open the dashboard
#    http://localhost:3000        (UI)
#    http://localhost:8000/docs   (API)
```

### Run the tests

```bash
cd backend
pip install -e ".[dev]"
pytest            # parsers, scorer (TP + FP), grounding guard, rulebook
```

### Prove detection quality on REAL attack data

```bash
# clone real labeled attack telemetry
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES data/external/evtx

python scripts/metrics.py \
  --benign data/samples/normal \
  --attack data/external/evtx \
  --min-severity high
# -> prints TPR, false positives / 1k events, per-technique breakdown,
#    and a copy-paste resume line.
```

## Project layout

```
backend/   FastAPI app (ingest, baseline, detect, narrate, graph, investigate, api)
frontend/  Next.js dashboard (Overview, Incidents, Graph, Investigations, Predictions)
scripts/   demo data generator + detection metrics harness
docs/       ARCHITECTURE.md, DETECTIONS.md, API.md
data/       sample datasets (provenance in data/README.md)
```

## Design decisions worth defending

- **Rule-based MITRE mapping**, not LLM — LLMs hallucinate technique IDs.
- **Attributable scoring** — `score = Σ(weight × signal)`, every point traceable.
- **Grounding guard** — narratives may only cite IPs/techniques in the evidence.
- **Local LLM** — SOC telemetry shouldn't leave the org; Ollama keeps it on-prem.
- **Deterministic agent** — a fixed LangGraph, not a free-roaming one, so output is reproducible.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §12 for the full list.
