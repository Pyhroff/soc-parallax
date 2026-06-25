# SOC PARALLAX — Architecture & Build Plan

> **Cyber Behavioral Intelligence Platform** — a blue-team project that learns per-entity
> behavioral baselines, scores anomalies, maps them to MITRE ATT&CK, and explains *why*
> something is suspicious in analyst-grade language.

**Status:** v1 architecture (pre-code). Author: solo build, blue-team portfolio project.

---

## 0. The honest framing (read this first)

This document deliberately builds a **vertical slice**, not the 8-module mega-spec.
Reason: a fresher targeting a 12 LPA SOC/detection role is screened on **depth and
defensibility**, not module count. One pipeline you understand end-to-end beats 500
generated files you can't explain in an interview.

The full 8-module vision lives in the README "Roadmap" section to show product thinking.
We *ship* the core. Kafka, OpenSearch, RBAC, and the ML predictor are explicitly
**deferred** — they are plumbing every employer already has and add risk without adding
interview value.

**What this project must prove to a hiring manager:**
1. You can parse and normalize real EDR telemetry (Sysmon / Windows Event Logs).
2. You can build a behavioral baseline and reason about anomalies (not just `if x > threshold`).
3. You can map findings to **MITRE ATT&CK** correctly.
4. You can produce **explainable, non-hallucinated** narratives (this is the differentiator).
5. You can measure detection quality (detection rate, false-positive rate) against real attack data.

If the project can't survive the question *"show me a true positive and a false positive
and explain why your engine scored each that way"* — it has failed, regardless of how
pretty the dashboard is.

---

## 1. Scope: v1 (build) vs Roadmap (README only)

| Module (original spec)          | v1 decision        | Why |
|---------------------------------|--------------------|-----|
| 1. Behavioral DNA Engine        | **BUILD**          | The core idea. Per-entity baselines + anomaly scoring. |
| 5. Narrative Intelligence       | **BUILD**          | The differentiator. Explainable findings via local LLM. |
| 2. Organizational Memory Graph  | **BUILD (lite)**   | Neo4j, but only the nodes/edges the slice needs. Strong "stretch" win. |
| 4. Autonomous Investigation     | **BUILD (minimal)**| A *small* deterministic LangGraph: collect → baseline → MITRE → narrate. No agent sprawl. |
| 3. Attack Genome Engine         | Roadmap            | Cool, but similarity scoring is easy to fake and hard to defend. Defer. |
| 6. Threat Evolution Predictor   | Roadmap            | Needs data you don't have. Defer (architecture leaves room). |
| 7. Attack Replay Engine         | Roadmap (UI later) | Timeline view is a nice-to-have on the incident page. |
| 8. SOC Command Center           | **BUILD (3 pages)**| Overview, Incident detail, Memory graph. Not 8 pages. |

**Stack actually used in v1:** FastAPI · Postgres · Neo4j · Ollama (local LLM) ·
Next.js + TypeScript + Tailwind · D3 (timeline) · Cytoscape (graph) · Docker Compose.

**Explicitly NOT in v1:** Kafka, OpenSearch, Redis, RBAC, MinIO, Kubernetes.
(All listed in roadmap with a one-line "why later".)

---

## 2. System architecture

```
                          ┌─────────────────────────────────────────┐
                          │            Next.js Frontend               │
                          │  Overview · Incident · Memory Graph       │
                          │  React Query · D3 timeline · Cytoscape    │
                          └───────────────────┬───────────────────────┘
                                              │ REST (JSON)
                          ┌───────────────────▼───────────────────────┐
                          │              FastAPI Backend                │
                          │                                             │
                          │  /ingest    parsers → normalizer → events   │
                          │  /baseline  build & query entity profiles   │
                          │  /detect    anomaly scoring + MITRE map     │
                          │  /investigate  LangGraph pipeline           │
                          │  /narrate   LLM narrative (grounded)        │
                          │  /graph     Neo4j queries                   │
                          └─────┬──────────────┬─────────────┬─────────┘
                                │              │             │
                    ┌───────────▼──┐   ┌───────▼──────┐  ┌───▼────────┐
                    │  PostgreSQL  │   │    Neo4j     │  │   Ollama   │
                    │ events,      │   │ entities &   │  │ llama3 /   │
                    │ baselines,   │   │ relationships│  │ mistral    │
                    │ detections,  │   │ (memory      │  │ (narrative │
                    │ incidents    │   │  graph)      │  │  only)     │
                    └──────────────┘   └──────────────┘  └────────────┘
```

**Data flow (one sentence each):**
1. **Ingest** — raw Sysmon/EVTX/JSON/CSV → parser → **unified event schema** → Postgres `events`.
2. **Baseline** — aggregate events per entity (user/host/process) into statistical profiles → Postgres `baselines`.
3. **Detect** — score new events against baseline; multi-signal anomalies → `detections` with MITRE technique IDs.
4. **Correlate** — group related detections into an `incident`; write entities/edges to Neo4j.
5. **Investigate** — LangGraph pipeline assembles timeline, anomalies, MITRE, indicators.
6. **Narrate** — LLM turns the *structured evidence* into an analyst narrative (grounded, no free invention).

---

## 3. Unified event schema (the foundation)

Everything normalizes to this. Get this right and the whole project is coherent.

```python
# Normalized event — the single schema all parsers emit
{
  "event_id":      "uuid",
  "timestamp":     "2026-06-08T14:22:01Z",   # ISO 8601 UTC
  "source":        "sysmon|winevent|json|csv",
  "event_type":    "process_create|network_connect|file_access|logon|...",
  "host":          "WORKSTATION-07",
  "user":          "ACME\\jdoe",
  "process": {
      "name":      "powershell.exe",
      "pid":       4821,
      "ppid":      992,
      "parent":    "explorer.exe",
      "cmdline":   "powershell -enc <base64>",
      "hashes":    {"sha256": "..."}
  },
  "network": {
      "dest_ip":   "185.220.101.5",
      "dest_port": 443,
      "direction": "outbound",
      "domain":    "evil.example"
  },
  "file":  {"path": "C:\\Users\\jdoe\\...", "action": "create"},
  "logon": {"type": 3, "result": "success", "src_ip": "..."},
  "raw":   { ... }   # original record, always preserved
}
```

**Sysmon Event ID → event_type mapping** (the parser table):

| Sysmon ID | event_type        | Key fields |
|-----------|-------------------|-----------|
| 1         | process_create    | Image, CommandLine, ParentImage, Hashes |
| 3         | network_connect   | DestinationIp, DestinationPort, Image |
| 7         | image_load        | ImageLoaded, Signed |
| 8         | create_remote_thread | SourceImage, TargetImage |
| 11        | file_create       | TargetFilename, Image |
| 13        | registry_set      | TargetObject, Details |
| 22        | dns_query         | QueryName, Image |

Windows Security log: 4624/4625 (logon), 4688 (process), 4672 (privilege), 4720 (account created).

---

## 4. PostgreSQL schema

```sql
-- Raw + normalized events
CREATE TABLE events (
    event_id     UUID PRIMARY KEY,
    timestamp    TIMESTAMPTZ NOT NULL,
    source       TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    host         TEXT,
    "user"       TEXT,
    process_name TEXT,
    cmdline      TEXT,
    dest_ip      INET,
    dest_port    INT,
    payload      JSONB NOT NULL,        -- full normalized record
    ingested_at  TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_events_entity ON events (host, "user", timestamp);
CREATE INDEX idx_events_type   ON events (event_type, timestamp);
CREATE INDEX idx_events_payload ON events USING GIN (payload);

-- Behavioral baselines: one row per (entity_type, entity_id, feature)
CREATE TABLE baselines (
    id            BIGSERIAL PRIMARY KEY,
    entity_type   TEXT NOT NULL,        -- user | host | process
    entity_id     TEXT NOT NULL,
    feature       TEXT NOT NULL,        -- login_hour | dest_ip | proc_name | ...
    distribution  JSONB NOT NULL,       -- {value: count} histogram, or mean/std
    sample_count  INT NOT NULL,
    first_seen    TIMESTAMPTZ,
    last_seen     TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ DEFAULT now(),
    UNIQUE (entity_type, entity_id, feature)
);

-- Detections: a scored anomaly
CREATE TABLE detections (
    detection_id  UUID PRIMARY KEY,
    event_id      UUID REFERENCES events(event_id),
    entity_type   TEXT,
    entity_id     TEXT,
    score         NUMERIC(5,2),          -- 0..100
    severity      TEXT,                  -- low|medium|high|critical
    signals       JSONB,                 -- [{name, weight, contribution, evidence}]
    mitre         JSONB,                 -- [{technique_id, tactic, name}]
    created_at    TIMESTAMPTZ DEFAULT now()
);

-- Incidents: a correlated cluster of detections
CREATE TABLE incidents (
    incident_id   UUID PRIMARY KEY,
    title         TEXT,
    status        TEXT DEFAULT 'open',   -- open|investigating|closed
    severity      TEXT,
    entity_id     TEXT,
    detection_ids UUID[],
    narrative     TEXT,                  -- generated, grounded
    mitre_chain   JSONB,
    created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE audit_log (             -- lightweight; not full RBAC
    id BIGSERIAL PRIMARY KEY,
    actor TEXT, action TEXT, target TEXT,
    detail JSONB, at TIMESTAMPTZ DEFAULT now()
);
```

---

## 5. Neo4j graph schema (memory graph)

Only the nodes/edges the slice actually uses. Don't model what you won't query.

```
(:User {name})          (:Host {name})        (:Process {name, hash})
(:IP {addr})            (:Domain {name})      (:FileHash {sha256})
(:Incident {id, severity, created_at})
(:Technique {id, name, tactic})       // MITRE ATT&CK

// Relationships
(:User)-[:LOGGED_INTO]->(:Host)
(:Host)-[:RAN]->(:Process)
(:Process)-[:SPAWNED]->(:Process)
(:Process)-[:CONNECTED_TO]->(:IP)
(:IP)-[:RESOLVES_TO]->(:Domain)
(:Process)-[:HAS_HASH]->(:FileHash)
(:Incident)-[:INVOLVES]->(:User|:Host|:Process|:IP)
(:Incident)-[:USED_TECHNIQUE]->(:Technique)
(:Technique)-[:PRECEDES]->(:Technique)   // for the future predictor
```

**Killer queries to demo in an interview:**
- "Show every host this user touched and the external IPs those hosts contacted" (lateral movement view).
- "Find incidents that share ≥2 MITRE techniques" (campaign clustering — your 'attack similarity' lite).
- "From technique T1059, what techniques historically followed?" (seed for the predictor).

---

## 6. Behavioral DNA Engine — how scoring actually works

Don't hand-wave this. The interview *will* drill here.

**Features per entity:**
| Entity  | Features |
|---------|----------|
| User    | login hour histogram, source IPs/geo, hosts logged into, processes spawned, privilege-use count |
| Host    | process set, parent→child pairs, outbound dest IPs/ports, PowerShell/admin tool frequency |
| Process | typical parent, typical args shape, network behavior, signed/unsigned |

**Baseline build:** over a training window (e.g. 30 days of "normal"), compute per-feature
distributions — frequency histograms for categoricals (login hour, dest IP), mean/std for
counts. Store in `baselines.distribution`.

**Anomaly scoring (per event):** combine signals, each producing a 0–1 sub-score:
- **Rarity** — `-log(p)` where `p` = observed frequency of this value in baseline (never-seen value → high).
- **Statistical** — z-score for numeric features (e.g. logon count this hour).
- **Contextual rules** — encoded PowerShell, parent mismatch (`winword.exe → powershell.exe`),
  first-time admin use, off-hours logon. These map directly to MITRE.

Final `score = 100 * weighted_sum(signals)`, with each signal's `contribution` stored so the
narrative can cite it. **This explainability — every point of the score is attributable — is
the whole pitch.** "It's not a black box; here are the 4 reasons it scored 87."

**Severity thresholds:** low <40 · medium 40–69 · high 70–89 · critical ≥90 (tune against data).

---

## 7. MITRE mapping & narrative (the differentiator)

**Mapping** is rule-driven, not LLM-guessed (LLMs hallucinate technique IDs):
```
encoded_powershell      → T1059.001 (PowerShell)
parent_child_anomaly    → T1055 / T1036 depending on pattern
new_admin_use           → T1078 (Valid Accounts) / T1068
off_hours_logon + new_ip→ T1078
suspicious_dns          → T1071.004
```
Keep a YAML rulebook: `signal → technique_id`. Versioned, testable, defensible.

**Narrative generation** — the LLM gets **structured evidence only** and is instructed to
explain, never to invent. Prompt contract:
```
INPUT (to LLM):
  entity, baseline summary, the triggering event, the list of fired signals with
  their contributions, mapped MITRE techniques.
RULES:
  - Reference ONLY the provided evidence. No new IPs, no new techniques.
  - Explain why each signal is abnormal relative to the baseline.
  - Output: 2-3 paragraphs, SOC-analyst tone, end with recommended next step.
```
This is how you get the "user hasn't run PowerShell in 90 days + abnormal login hour +
outbound connection = likely post-compromise" narrative — **grounded**, because every fact
came from the evidence object, not the model's imagination. Add a guard: post-check that no
IP/technique in the narrative is absent from the evidence (anti-hallucination test).

---

## 8. Autonomous Investigation (LangGraph — keep it small)

A **deterministic** graph, not a free-roaming agent. 5 nodes:
```
collect ─→ baseline_compare ─→ mitre_map ─→ correlate ─→ narrate
```
- `collect`: pull events for the entity/time window from Postgres.
- `baseline_compare`: run scoring, gather fired signals.
- `mitre_map`: apply the YAML rulebook.
- `correlate`: query Neo4j for related entities/incidents.
- `narrate`: call the LLM with the evidence bundle.

State object carries everything; each node is a pure function over state (testable).
**Show the reasoning** — return each node's output so the UI can display the chain. That
"glass box agent" visibility is itself a talking point.

---

## 9. Folder structure

```
SOC-PARALLAX/
├── docker-compose.yml          # postgres, neo4j, ollama, backend, frontend
├── README.md                   # vision + roadmap + screenshots + metrics
├── docs/
│   ├── ARCHITECTURE.md         # this file
│   ├── DETECTIONS.md           # each rule, its MITRE map, its logic
│   └── API.md                  # endpoint contracts
├── backend/
│   ├── pyproject.toml
│   ├── alembic/                # migrations
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── db/                 # postgres + neo4j clients
│   │   ├── schemas/            # pydantic: UnifiedEvent, Detection, ...
│   │   ├── ingest/
│   │   │   ├── parsers/        # sysmon.py, winevent.py, json.py, csv.py
│   │   │   └── normalizer.py
│   │   ├── baseline/engine.py
│   │   ├── detect/
│   │   │   ├── scorer.py
│   │   │   ├── signals/        # rarity.py, statistical.py, rules.py
│   │   │   └── mitre.yaml
│   │   ├── investigate/graph.py   # LangGraph
│   │   ├── narrate/llm.py         # Ollama abstraction + grounding guard
│   │   ├── graph/queries.py       # Neo4j cypher
│   │   └── api/routes/
│   └── tests/
│       ├── test_parsers.py
│       ├── test_scorer.py         # true-positive & false-positive fixtures
│       └── test_narrative_grounding.py   # anti-hallucination test
├── frontend/
│   ├── app/
│   │   ├── page.tsx               # Overview
│   │   ├── incidents/[id]/page.tsx# Incident detail + timeline + narrative
│   │   └── graph/page.tsx         # Cytoscape memory graph
│   ├── components/
│   └── lib/api.ts
├── data/
│   ├── samples/                   # labeled normal + attack datasets
│   └── README.md                  # provenance of every dataset
└── scripts/
    ├── seed_baseline.py
    └── replay_attack.py           # feeds an attack scenario through the pipeline
```

---

## 10. Sample data — use REAL attack data, this is critical

Do **not** fabricate logs. Hiring managers can smell synthetic data. Use:
- **EVTX-ATTACK-SAMPLES** (github.com/sbousseaden/EVTX-ATTACK-SAMPLES) — real Sysmon/EVTX
  logs of actual ATT&CK techniques, already labeled by technique. Gold for this project.
- **Mordor / Security Datasets** (securitydatasets.com) — pre-recorded attack telemetry.
- **Atomic Red Team** — if you have a Windows VM, run atomics and capture your own Sysmon
  (the strongest possible flex: "I generated this telemetry myself").
- For the "normal" baseline: your own VM's day-to-day Sysmon, or the benign portions of the above.

Then you can put a **real metric** on your resume: *"Detected N/M ATT&CK techniques from the
EVTX-ATTACK-SAMPLES corpus at X% TPR with Y false positives per 1k events."* That single line
beats every buzzword.

---

## 11. Build roadmap (realistic, solo)

| Phase | Deliverable | Done when |
|-------|-------------|-----------|
| **0** | Repo, docker-compose (postgres+neo4j+ollama up), schemas, CI | `docker compose up` works; pydantic schemas defined |
| **1** | Ingest: Sysmon + EVTX parser → normalizer → Postgres | Can load EVTX-ATTACK-SAMPLES; events queryable |
| **2** | Baseline engine + seed script | Baselines built from a training window |
| **3** | Detect: scorer + signals + MITRE rulebook | True/false-positive fixtures pass; detections written |
| **4** | Narrative (Ollama) + grounding guard | Narratives generated; anti-hallucination test passes |
| **5** | Neo4j memory graph + correlation | Entities/edges written; campaign-clustering query works |
| **6** | LangGraph investigation pipeline | `/investigate` returns chain + narrative |
| **7** | Frontend: Overview + Incident + Graph pages | Click a detection → see timeline, signals, narrative, graph |
| **8** | Metrics run + README with screenshots + numbers | TPR/FP table in README; demo GIF |

Each phase = a clean commit/PR with tests. Your **git history becomes evidence** that you
built it incrementally and understand it — that itself is interview gold.

---

## 12. Decisions you should be ready to defend (write these in DETECTIONS.md)

- Why `-log(p)` rarity instead of plain thresholds? (handles unseen values, attributable.)
- Why rule-based MITRE mapping instead of asking the LLM? (LLMs hallucinate technique IDs.)
- Why Neo4j over doing it in Postgres with recursive CTEs? (multi-hop traversal + clustering ergonomics.)
- Why local LLM (Ollama) over an API? (data sensitivity — SOC telemetry shouldn't leave the org; cost.)
- Where does it produce false positives, and how would you tune it? (Have an honest answer. "It's perfect" is a lie they'll catch.)
```
