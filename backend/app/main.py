"""SOC PARALLAX — FastAPI application entrypoint."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.config import settings
from app.api.auth import require
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
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)

app.include_router(ingest.router)
app.include_router(analytics.router)


@app.get("/health", tags=["meta"])
def health() -> dict:
    """Unauthenticated liveness only: no dependency details are exposed."""
    return {"app": "ok"}


@app.get("/health/deps", tags=["meta"], dependencies=[Depends(require("analyst"))])
def health_deps() -> dict:
    status = {"app": "ok"}
    for name, fn in (("postgres", lambda: postgres.query("SELECT 1")),
                     ("neo4j", lambda: neo4j.run("RETURN 1"))):
        try:
            fn()
            status[name] = "ok"
        except Exception:
            status[name] = "unavailable"
    return status
