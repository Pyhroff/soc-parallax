"""PostgreSQL access via a psycopg3 connection pool.

Raw SQL on purpose: in a SOC tool you want to be able to say exactly what query
runs. No ORM magic to defend in an interview.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any, Iterator

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from app.config import settings

_pool: ConnectionPool | None = None


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(settings.pg_dsn, min_size=1, max_size=10, open=True)
    return _pool


@contextmanager
def get_conn() -> Iterator[Any]:
    pool = get_pool()
    with pool.connection() as conn:
        yield conn


def query(sql: str, params: tuple | dict | None = None) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            if cur.description is None:
                return []
            return cur.fetchall()


def execute(sql: str, params: tuple | dict | None = None) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
        conn.commit()


def as_jsonb(value: Any) -> str:
    """Serialize a Python object for a JSONB column (psycopg needs a str/Json)."""
    return json.dumps(value, default=str)


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None
