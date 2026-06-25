"""SOC PARALLAX — FastAPI application entrypoint."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.routes import analytics, ingest
from app.db import neo4j, postgres


@asynccontextmanager
async def lifespan(app: FastAPI):
    # warm the pg pool; ensure graph constraints (best-effort)
    try:
        postgres.get_pool()
    except Exception:
        pass
    try:
        neo4j.ensure_constraints()
    except Exception:
        pass
    yield
    postgres.close_pool()
    neo4j.close_driver()


app = FastAPI(
    title="SOC PARALLAX",
    description="Cyber Behavioral Intelligence Platform",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # dev only; lock down for prod
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest.router)
app.include_router(analytics.router)


@app.get("/health", tags=["meta"])
def health() -> dict:
    status = {"app": "ok"}
    try:
        postgres.query("SELECT 1")
        status["postgres"] = "ok"
    except Exception as exc:
        status["postgres"] = f"error: {exc}"
    try:
        neo4j.run("RETURN 1")
        status["neo4j"] = "ok"
    except Exception as exc:
        status["neo4j"] = f"error: {exc}"
    return status
