"""Neo4j driver wrapper for the Organizational Memory Graph."""
from __future__ import annotations

from typing import Any

from neo4j import Driver, GraphDatabase

from app.config import settings

_driver: Driver | None = None


def get_driver() -> Driver:
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
    return _driver


def run(cypher: str, params: dict | None = None) -> list[dict]:
    driver = get_driver()
    with driver.session() as session:
        result = session.run(cypher, params or {})
        return [record.data() for record in result]


def write(cypher: str, params: dict | None = None) -> Any:
    driver = get_driver()
    with driver.session() as session:
        return session.execute_write(lambda tx: tx.run(cypher, params or {}).consume())


def ensure_constraints() -> None:
    """Idempotent uniqueness constraints — safe to call on startup."""
    stmts = [
        "CREATE CONSTRAINT user_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE",
        "CREATE CONSTRAINT host_name IF NOT EXISTS FOR (h:Host) REQUIRE h.name IS UNIQUE",
        "CREATE CONSTRAINT ip_addr  IF NOT EXISTS FOR (i:IP)   REQUIRE i.addr IS UNIQUE",
        "CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
        "CREATE CONSTRAINT hash_sha  IF NOT EXISTS FOR (f:FileHash) REQUIRE f.sha256 IS UNIQUE",
        "CREATE CONSTRAINT tech_id   IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
        "CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (i:Incident) REQUIRE i.id IS UNIQUE",
    ]
    driver = get_driver()
    with driver.session() as session:
        for stmt in stmts:
            session.run(stmt)


def close_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None
