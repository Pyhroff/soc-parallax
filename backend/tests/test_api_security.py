"""API security: authentication, role separation, path containment, limits.
Uses FastAPI's TestClient without the lifespan, so no database is needed."""
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app

client = TestClient(app)          # no `with`: lifespan (DB warm-up) is not run


@pytest.fixture(autouse=True)
def keys(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "auth_disabled", False)
    monkeypatch.setattr(settings, "api_key_admin", "admin-key")
    monkeypatch.setattr(settings, "api_key_ingest", "ingest-key")
    monkeypatch.setattr(settings, "api_key_analyst", "analyst-key")
    root = tmp_path / "data"
    root.mkdir()
    (root / "ok.json").write_text("[]")
    monkeypatch.setattr(settings, "ingest_root", str(root))
    return root


def H(k):
    return {"X-API-Key": k}


def test_no_key_is_rejected_and_health_is_minimal():
    assert client.get("/incidents").status_code == 401
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"app": "ok"}


def test_wrong_key_rejected():
    assert client.get("/incidents", headers=H("nope")).status_code == 401


def test_fails_closed_when_no_keys_configured(monkeypatch):
    for f in ("api_key_admin", "api_key_ingest", "api_key_analyst"):
        monkeypatch.setattr(settings, f, "")
    assert client.get("/incidents", headers=H("")).status_code == 401
    assert client.get("/incidents", headers=H("anything")).status_code == 401


def test_analyst_cannot_ingest_or_rebuild_baselines():
    assert client.post("/ingest/file", json={"path": "ok.json"}, headers=H("analyst-key")).status_code == 403
    assert client.post("/baseline/build", json={}, headers=H("analyst-key")).status_code == 403


def test_ingest_role_cannot_rebuild_baselines():
    assert client.post("/baseline/build", json={}, headers=H("ingest-key")).status_code == 403
    assert client.post("/ingest/pipeline", json={"path": "."}, headers=H("ingest-key")).status_code == 403


@pytest.mark.parametrize("bad", ["../../etc/passwd", "/etc/passwd", "..", "sub/../../x"])
def test_path_traversal_rejected(bad):
    r = client.post("/ingest/file", json={"path": bad}, headers=H("ingest-key"))
    assert r.status_code == 400
    assert "etc" not in r.text and "passwd" not in r.text


def test_symlink_escape_rejected(keys, tmp_path):
    outside = tmp_path / "secret.json"
    outside.write_text("[]")
    (keys / "link.json").symlink_to(outside)
    r = client.post("/ingest/file", json={"path": "link.json"}, headers=H("ingest-key"))
    assert r.status_code == 400


def test_unsupported_extension_and_size_cap(keys, monkeypatch):
    (keys / "x.exe").write_text("MZ")
    assert client.post("/ingest/file", json={"path": "x.exe"}, headers=H("ingest-key")).status_code == 400
    monkeypatch.setattr(settings, "max_ingest_file_bytes", 1)
    (keys / "big.json").write_text("[1,2,3]")
    assert client.post("/ingest/file", json={"path": "big.json"}, headers=H("ingest-key")).status_code == 400


def test_record_count_cap(monkeypatch):
    monkeypatch.setattr(settings, "max_records_per_request", 2)
    r = client.post("/ingest/records", json=[{}, {}, {}], headers=H("ingest-key"))
    assert r.status_code == 413


def test_cors_is_not_wildcard():
    r = client.options("/incidents", headers={"Origin": "https://evil.example",
                                              "Access-Control-Request-Method": "GET"})
    assert r.headers.get("access-control-allow-origin") != "*"
    assert "evil.example" not in r.headers.get("access-control-allow-origin", "")
