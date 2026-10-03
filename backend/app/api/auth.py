"""API-key authentication with three roles.

  analyst  read endpoints + investigate
  ingest   analyst + ingest, detect, correlate
  admin    everything, including rebuilding baselines

Keys come from the environment. With no keys configured the API fails closed
(401) unless AUTH_DISABLED=true is set deliberately for local development.
Keys are compared in constant time.
"""
from __future__ import annotations

import hmac
import logging

from fastapi import Depends, HTTPException, Request
from fastapi.security import APIKeyHeader

from app.config import settings

log = logging.getLogger("parallax.auth")
_header = APIKeyHeader(name="X-API-Key", auto_error=False)
RANK = {"analyst": 1, "ingest": 2, "admin": 3}


def _role_for(key: str) -> str | None:
    role = None
    for name, configured in (("analyst", settings.api_key_analyst),
                             ("ingest", settings.api_key_ingest),
                             ("admin", settings.api_key_admin)):
        # evaluate every comparison (no early exit) so timing does not reveal which key matched
        if configured and hmac.compare_digest(key.encode(), configured.encode()):
            role = name
    return role


def require(min_role: str):
    need = RANK[min_role]

    def dep(request: Request, key: str | None = Depends(_header)) -> str:
        if settings.auth_disabled:
            return "admin"
        role = _role_for(key) if key else None
        if role is None or RANK[role] < need:
            log.warning("auth denied: path=%s role_needed=%s client=%s", request.url.path, min_role,
                        request.client.host if request.client else "?")
            # same response whether the key is missing, wrong, or merely too weak
            raise HTTPException(401 if role is None else 403,
                                "Unauthorized" if role is None else "Forbidden")
        return role

    return dep
