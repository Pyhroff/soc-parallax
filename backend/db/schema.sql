-- SOC PARALLAX — PostgreSQL schema
-- Loaded automatically by the postgres container on first start.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- for gen_random_uuid()

-- ---------------------------------------------------------------------------
-- events : raw + normalized telemetry (unified event schema)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    event_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "timestamp"  TIMESTAMPTZ NOT NULL,
    source       TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    host         TEXT,
    "user"       TEXT,
    process_name TEXT,
    cmdline      TEXT,
    dest_ip      INET,
    dest_port    INT,
    payload      JSONB NOT NULL,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_entity  ON events (host, "user", "timestamp");
CREATE INDEX IF NOT EXISTS idx_events_type    ON events (event_type, "timestamp");
CREATE INDEX IF NOT EXISTS idx_events_payload ON events USING GIN (payload);

-- ---------------------------------------------------------------------------
-- baselines : one row per (entity_type, entity_id, feature)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS baselines (
    id            BIGSERIAL PRIMARY KEY,
    entity_type   TEXT NOT NULL,          -- user | host | process
    entity_id     TEXT NOT NULL,
    feature       TEXT NOT NULL,          -- login_hour | dest_ip | process_name | parent_child | ...
    distribution  JSONB NOT NULL,         -- {"value": count, ...} or {"mean":..,"std":..}
    sample_count  INT  NOT NULL DEFAULT 0,
    first_seen    TIMESTAMPTZ,
    last_seen     TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (entity_type, entity_id, feature)
);
CREATE INDEX IF NOT EXISTS idx_baselines_entity ON baselines (entity_type, entity_id);

-- ---------------------------------------------------------------------------
-- detections : a scored anomaly
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detections (
    detection_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id      UUID REFERENCES events(event_id) ON DELETE CASCADE,
    entity_type   TEXT,
    entity_id     TEXT,
    score         NUMERIC(5,2) NOT NULL,
    severity      TEXT NOT NULL,          -- low|medium|high|critical
    signals       JSONB NOT NULL,         -- [{name, weight, contribution, evidence, mitre}]
    mitre         JSONB NOT NULL,         -- [{technique_id, tactic, name}]
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_detections_entity   ON detections (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections (severity, created_at);

-- ---------------------------------------------------------------------------
-- incidents : a correlated cluster of detections
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    incident_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title         TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'open',   -- open|investigating|closed
    severity      TEXT NOT NULL,
    entity_type   TEXT,
    entity_id     TEXT,
    detection_ids UUID[] NOT NULL DEFAULT '{}',
    narrative     TEXT,
    mitre_chain   JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status, created_at);

-- ---------------------------------------------------------------------------
-- audit_log : lightweight action trail (not full RBAC)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id      BIGSERIAL PRIMARY KEY,
    actor   TEXT,
    action  TEXT NOT NULL,
    target  TEXT,
    detail  JSONB,
    at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
