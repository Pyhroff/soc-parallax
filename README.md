# SOC PARALLAX

**Cyber Behavioral Intelligence Platform** — learns per-entity behavioral
baselines, scores anomalies with a fully *attributable* risk score, maps them to
MITRE ATT&CK, correlates them into incidents in a memory graph, and explains
*why* something is suspicious in grounded, analyst-grade language.

> Not a SIEM. Not a log viewer. SOC PARALLAX answers *what is happening*,
> *what happened before*, and *what is likely to happen next* — and shows its work.

[![tests](https://github.com/Pyhroff/soc-parallax/actions/workflows/test.yml/badge.svg)](https://github.com/Pyhroff/soc-parallax/actions/workflows/test.yml) ![TPR](https://img.shields.io/badge/TPR-53%25-orange) ![FP](https://img.shields.io/badge/FP%2F1k-0.0-brightgreen) ![stack](https://img.shields.io/badge/stack-FastAPI%20%7C%20Neo4j%20%7C%20Next.js-blue)

> **Detection results** (real [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) corpus, 279 attack files):
> 53% TPR · **0.0 false positives per 1,000 events**

---

## Why this exists

Most detection demos are black boxes: "the model flagged it." SOC PARALLAX is a
**glass box** — every point of a risk score traces to a named signal, every
MITRE mapping comes from a versioned rulebook (not an LLM guess), and every
generated narrative passes an **anti-hallucination check** before it's shown.

## Why this matters

False-positive fatigue is the actual reason most SOC anomaly detectors fail in practice, not a lack of detection coverage. A model that flags everything mildly unusual generates thousands of alerts a day; analysts stop reading them, and the one real intrusion gets lost in the noise — this is a documented, widely-cited failure mode in real security operations, not a hypothetical. SOC PARALLAX's benchmark against the real, labeled [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) corpus (279 real attack telemetry files, not synthetic data) is 53% TPR at **0.0 false positives per 1,000 events** — and the reason that's trustworthy rather than a lucky number on one dataset is the architecture behind it: every risk score traces back to a named, weighted signal (`score = Σ(weight × signal)`), every MITRE ATT&CK mapping comes from a versioned YAML rulebook rather than an LLM's guess at a technique ID, and every generated narrative passes a grounding guard that blocks it from citing an IP or technique that isn't actually in the evidence. That's the actual bet this project makes: an analyst should be able to click into any single point of any score and see exactly which signal produced it — the opposite of "the model flagged it" with no further explanation, which is what most detection demos still ship.

## Demo

<!--
  TODO(Blessing): replace this line with the recorded GIF, e.g.:
  ![SOC PARALLAX dashboard](docs/demo.gif)

  How to record it (5-10 minutes, needs Docker running):
  1. `docker compose up --build` (first run pulls images, takes a few minutes)
  2. `docker exec parallax-ollama ollama pull llama3` (first run only)
  3. `python scripts/generate_demo_data.py` to get sample data to show
  4. Run the ingest pipeline (see Quickstart step 4 above) so the dashboard
     has real incidents/detections to display, not an empty state
  5. Open http://localhost:3000 in a browser window sized to ~1200x700
  6. Record with a free screen-to-GIF tool:
       - Windows: ScreenToGif (screentogif.com)
       - Or record .mp4 (OBS / Xbox Game Bar) and convert:
         ffmpeg -i demo.mp4 -vf "fps=10,scale=1200:-1" -loop 0 docs/demo.gif
  7. Good things to capture in order: the Overview page with real numbers,
     clicking into one Incident to show the MITRE mapping + narrative +
     "why" trace, then the Graph view. 10-20 seconds total is plenty.
  8. Keep the file under ~8-10MB; `gifsicle -O3` helps if it's too big.
  9. Save to docs/demo.gif and replace this comment block with the
     ![...](docs/demo.gif) line above.
-->

*(GIF coming soon — see the Quickstart above to run it yourself in the meantime.)*

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
#    and a summary line for reporting.
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
