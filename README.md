# SOC PARALLAX

**Cyber Behavioral Intelligence Platform** - learns per-entity behavioral
baselines, scores anomalies with a fully *attributable* risk score, maps them to
MITRE ATT&CK, correlates them into incidents in a memory graph, and explains
*why* something is suspicious in grounded, analyst-grade language.

> Not a SIEM. Not a log viewer. SOC PARALLAX answers *what is happening*,
> *what happened before*, and *what is likely to happen next* - and shows its work.

[![tests](https://github.com/Pyhroff/soc-parallax/actions/workflows/test.yml/badge.svg)](https://github.com/Pyhroff/soc-parallax/actions/workflows/test.yml) ![stack](https://img.shields.io/badge/stack-FastAPI%20%7C%20Neo4j%20%7C%20Next.js-blue)

> **Measured results** ([method and caveats](docs/EVALUATION.md)): on 278 real EVTX-ATTACK-SAMPLES files, rules fire on 36%
> and reach medium severity or higher on 29.5% (27.3% on a held-out half used only for reporting). On held-out benign
> data (known and unseen users), nothing reaches high severity. 16.5% of the corpus still does not parse. These replace
> an earlier, inflated 53% / 0.0 figure.

---

## Why this exists

Most detection demos are black boxes: "the model flagged it." SOC PARALLAX is a
**glass box** - every point of a risk score traces to a named signal, every
MITRE mapping comes from a versioned rulebook (not an LLM guess), and every
generated narrative passes an **anti-hallucination check** before it's shown.

## Why this matters

False-positive fatigue is why most anomaly detectors get ignored, so this project is built around restraint:
a baseline anomaly alone can never exceed medium severity, a new user or host with no history produces no
rarity signal at all, and high or critical severity requires a contextual rule to have fired. The first version
of this project did not behave that way (it flagged every unseen entity as critical and reported 53% detection
on that basis); the audit that found it, and the corrected numbers, are in [`docs/EVALUATION.md`](docs/EVALUATION.md).
Every score still traces to named, weighted signals (`score = Σ(weight × signal)`), ATT&CK mappings come from a
versioned YAML rulebook rather than a model, and generated narratives are checked against the evidence before
they are shown.

## Demo


*(No recording yet; see the Quickstart to run it locally.)*

## What's built (the vertical slice)

| Module | Status | What it does |
|--------|--------|--------------|
| Ingest pipeline |  | Sysmon/EVTX, Windows Event, JSON/ECS, CSV → unified event schema |
| Behavioral baselines |  | Per-user/host histograms; smoothed rarity, ignored until 50 observations |
| Detection + MITRE |  | Attributable signals, YAML ATT&CK rulebook |
| Narrative intelligence |  | Local LLM (Ollama) narratives with a grounding guard |
| Organizational memory graph |  | Neo4j entities/edges, per-host process nodes; host exposure (not attribution), shared-technique clustering |
| Investigation workflow |  | Fixed (non-agentic) LangGraph pipeline: collect→baseline→mitre→correlate→narrate |
| SOC command center |  | Next.js dark UI: Overview, Incidents, Graph, Investigations, Predictions |
| Threat evolution predictor | ◑ | Counts of which technique was observed after which (not a predictive model) |

### Roadmap (designed for, not yet built)
Attack Genome similarity engine · Kafka streaming ingest · OpenSearch full-text ·
multi-tenant isolation · Attack Replay step-through · Kubernetes deploy. See
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
# 0. secrets: copy .env.example to .env and fill every value (compose refuses to start without them)
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"   # run once per value

# 1. bring up postgres + neo4j + ollama + backend + frontend (ports bind to localhost only)
docker compose up --build

# 2. pull a local model for narratives (first run only)
docker exec parallax-ollama ollama pull llama3

# 3. generate the synthetic demo dataset (deterministic)
python scripts/generate_demo_data.py

# 4. label the normal data as baseline, ingest it, build baselines, then ingest and score the rest
KEY=<your API_KEY_ADMIN>
curl -X POST localhost:8000/ingest/dir -H "X-API-Key: $KEY" -H 'content-type: application/json' \
     -d '{"path":"samples/normal","dataset":"baseline"}'
curl -X POST localhost:8000/baseline/build -H "X-API-Key: $KEY" -H 'content-type: application/json' -d '{}'
curl -X POST localhost:8000/ingest/pipeline -H "X-API-Key: $KEY" -H 'content-type: application/json' \
     -d '{"path":"samples/attack"}'

# 5. open the dashboard
#    http://localhost:3000        (UI; talks to the API through a server-side proxy holding the analyst key)
#    http://localhost:8000/docs   (API)
```

Ingestion paths are relative to `INGEST_ROOT` (`/data` in the container) and cannot leave it.
Baselines are built only from events ingested with `"dataset":"baseline"`, so telemetry that
arrives later cannot teach the model that attacker behavior is normal.

### Run the tests

```bash
cd backend
pip install -e ".[dev]"
pytest            # parsers, scorer (TP + FP), grounding guard, rulebook
```

### Reproduce the evaluation

See [`docs/EVALUATION.md`](docs/EVALUATION.md) for the method, results and limits.

## Project layout

```
backend/   FastAPI app (ingest, baseline, detect, narrate, graph, investigate, api)
frontend/  Next.js dashboard (Overview, Incidents, Graph, Investigations, Predictions)
scripts/   demo data generator + detection metrics harness
docs/       ARCHITECTURE.md, DETECTIONS.md, EVALUATION.md, API.md
data/       sample datasets (provenance in data/README.md)
```

## Design decisions worth defending

- **Rule-based MITRE mapping**, not LLM - LLMs hallucinate technique IDs.
- **Attributable scoring** - `score = Σ(weight × signal)`, every point traceable.
- **Grounding guard** - narratives may only cite IPs/techniques in the evidence.
- **Local LLM** - SOC telemetry shouldn't leave the org; Ollama keeps it on-prem.
- **Deterministic workflow** - a fixed LangGraph pipeline, not an agent, so output is reproducible.
- **Restraint over recall** - rarity alone is capped at medium; high needs a rule.
- **Secure by default** - API keys with roles (fail closed), path-confined ingest, no default secrets, non-root containers.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §12 for the full list.
