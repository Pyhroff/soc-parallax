"""Central configuration — single source of truth, read from env."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Postgres
    pg_dsn: str = ""                  # required: set PG_DSN (no default credentials)

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""          # no default secret; supplied via env / compose

    # Ollama (local LLM)
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    ollama_timeout: float = 120.0

    # Detection tuning
    training_window_days: int = 30
    severity_low: float = 40.0
    severity_medium: float = 70.0
    severity_critical: float = 90.0
    # Rarity needs history: a baseline with fewer observations than this is treated as
    # "no history" and produces NO rarity signal (new entities are not auto-flagged).
    min_baseline_samples: int = 50
    # A detection with no contextual rule behind it (baseline anomaly only) cannot exceed this
    # score, i.e. it tops out at "medium": rarity is a triage hint, not proof of compromise.
    rarity_only_cap: float = 69.0

    # Correlation: detections within this window for the same entity form one incident
    correlation_window_minutes: int = 30

    # ---- API security ----
    # Keys are supplied via env. With no key configured the API fails closed (401) unless
    # AUTH_DISABLED=true is set explicitly for local development.
    api_key_admin: str = ""     # baseline rebuild, ingest, everything
    api_key_ingest: str = ""    # ingest + detect only
    api_key_analyst: str = ""   # read-only (+ investigate)
    auth_disabled: bool = False
    cors_origins: str = "http://localhost:3000"   # comma-separated

    # ---- Ingestion limits ----
    ingest_root: str = "/data"                 # file/dir ingestion is confined to this tree
    max_ingest_file_bytes: int = 50 * 1024 * 1024
    max_ingest_files: int = 500
    max_records_per_request: int = 5000


settings = Settings()
