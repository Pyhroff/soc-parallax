"""Central configuration — single source of truth, read from env."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Postgres
    pg_dsn: str = "postgresql://parallax:parallax@localhost:5432/parallax"

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "parallaxgraph"

    # Ollama (local LLM)
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    ollama_timeout: float = 120.0

    # Detection tuning
    training_window_days: int = 30
    severity_low: float = 40.0
    severity_medium: float = 70.0
    severity_critical: float = 90.0

    # Correlation: detections within this window for the same entity form one incident
    correlation_window_minutes: int = 30


settings = Settings()
