"""Confine file ingestion to a directory tree and cap what one request can read."""
from __future__ import annotations

import os

from app.config import settings

ALLOWED_EXT = (".evtx", ".json", ".ndjson", ".csv")


class PathRejected(ValueError):
    """Raised with a client-safe message; details go to the log, not the client."""


def resolve_inside_root(user_path: str) -> str:
    root = os.path.realpath(settings.ingest_root)
    full = os.path.realpath(os.path.join(root, user_path))      # follows symlinks
    if full != root and not full.startswith(root + os.sep):
        raise PathRejected("path is outside the ingest root")
    if not os.path.exists(full):
        raise PathRejected("path not found")
    return full


def check_file(full: str) -> None:
    if os.path.splitext(full)[1].lower() not in ALLOWED_EXT:
        raise PathRejected("unsupported file type")
    if os.path.getsize(full) > settings.max_ingest_file_bytes:
        raise PathRejected("file too large")


def list_files(full_dir: str) -> list[str]:
    root = os.path.realpath(settings.ingest_root)
    out: list[str] = []
    for base, _dirs, names in os.walk(full_dir, followlinks=False):
        for n in names:
            p = os.path.realpath(os.path.join(base, n))
            if p.startswith(root + os.sep) and n.lower().endswith(ALLOWED_EXT):
                out.append(p)
                if len(out) > settings.max_ingest_files:
                    raise PathRejected("too many files in directory")
    return sorted(out)
