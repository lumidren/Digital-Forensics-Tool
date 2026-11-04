"""Routes and pipeline paths not covered by test_api.py: admin, collaboration CRUD, analytics views,
exports, register-path ingest, triage bundles, WebSocket progress, manage commands."""
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from veritas.api import manage
from veritas.api.auth import hash_password
from veritas.api.config import load
from veritas.api.db import User
from veritas.api.main import create_app
from veritas.timeline.schema import Desc, Event

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "testdata" / "corpus" / "plaso"
BIN = ROOT / "target" / "release"
PW = "extended-test-password"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "var"))
    monkeypatch.setenv("VERITAS_MASTER_KEY", "66" * 32)
    monkeypatch.setenv("VERITAS_BIN_DIR", str(BIN))
    app = create_app(load(), start_processor=False)
    ctx = app.state.ctx
    with ctx.Session() as s:
        s.add_all([User(id="admin", display_name="Admin", password_hash=hash_password(PW), is_admin=True, can_unmask_pii=True),
                   User(id="alice", display_name="Alice", password_hash=hash_password(PW)),
                   User(id="carol", display_name="Carol", password_hash=hash_password(PW))])
        s.commit()
    with TestClient(app) as c:
        yield c, app


def tok(c, u):
    return {"Authorization": "Bearer " + c.post("/api/v1/auth/login", json={"username": u, "password": PW}).json()["access_token"]}


def test_admin_routes(env):
    c, app = env
    adm, alice = tok(c, "admin"), tok(c, "alice")
    assert c.post("/api/v1/admin/users", json={"id": "dave", "display_name": "Dave", "password": "dave-password-long"}, headers=adm).status_code == 201
    assert c.post("/api/v1/admin/users", json={"id": "dave", "display_name": "Dave"}, headers=adm).status_code == 409
    assert c.patch("/api/v1/admin/users/dave", json={"password": "short"}, headers=adm).status_code == 422
    assert c.patch("/api/v1/admin/users/nobody", json={}, headers=adm).status_code == 404
    assert c.patch("/api/v1/admin/users/dave", json={"display_name": "David", "can_unmask_pii": True}, headers=adm).status_code == 200
    reg = c.get("/api/v1/admin/keys", headers=alice).json()
    assert any(k["holder"] == "dave" for k in reg["keys"])
    assert c.patch("/api/v1/admin/users/dave", json={"active": False}, headers=adm).status_code == 200
    reg = c.get("/api/v1/admin/keys", headers=adm).json()
    assert next(k for k in reg["keys"] if k["holder"] == "dave")["valid_to"] is not None
    assert c.post("/api/v1/auth/login", json={"username": "dave", "password": "dave-password-long"}).status_code == 401
    assert c.post("/api/v1/admin/keys/carol/revoke", headers=adm).json()["revoked_key_id"] is None  # carol never had a key
    assert c.post("/api/v1/admin/retention/sweep", headers=adm).json() == {"due_for_disposal": []}
    assert c.get("/api/v1/admin/store/verify", headers=adm).json()["failed"] == []
    assert len(c.get("/api/v1/admin/audit", params={"actor": "admin"}, headers=adm).json()) > 0
    assert c.get("/readyz").json()["status"] == "ready"
    assert "T1003.001" in c.get("/api/v1/meta/attack", headers=alice).json()
    assert c.get("/api/v1/meta/roles").json()["case_roles"][0] == "viewer"


def test_collaboration_and_views(env):
    c, app = env
    a = tok(c, "alice")
    cid = c.post("/api/v1/cases", json={"name": "Collab", "timezone": "Europe/Berlin"}, headers=a).json()["id"]
    assert c.patch(f"/api/v1/cases/{cid}", json={"status": "review", "legal_hold": True, "retention_days": 30}, headers=a).json()["legal_hold"] is True
    assert c.post(f"/api/v1/cases/{cid}/members", json={"user_id": "ghost", "role": "viewer"}, headers=a).status_code == 404
    c.post(f"/api/v1/cases/{cid}/members", json={"user_id": "carol", "role": "viewer"}, headers=a)
    c.post(f"/api/v1/cases/{cid}/members", json={"user_id": "carol", "role": "examiner"}, headers=a)
    assert c.get(f"/api/v1/cases/{cid}", headers=a).json()["members"] == [{"user_id": "alice", "role": "lead"}, {"user_id": "carol", "role": "examiner"}]
    assert c.delete(f"/api/v1/cases/{cid}/members/carol", headers=a).json()["ok"]
    ev = Event(data_type="x", timestamp_desc=Desc.EVENT, message="m", timestamp=1, evidence_sha256="e" * 64, evidence_path="p")
    app.state.ctx.timeline.ingest(cid, [ev])
    eid = c.post(f"/api/v1/cases/{cid}/timeline/search", json={}, headers=a).json()["events"][0]["id"]
    assert c.get(f"/api/v1/cases/{cid}/events/{eid}", headers=a).json()["message"] == "m"
    assert c.get(f"/api/v1/cases/{cid}/events/99999", headers=a).status_code == 404
    assert c.post(f"/api/v1/cases/{cid}/bookmarks", json={"event_id": 99999}, headers=a).status_code == 404
    bid = c.post(f"/api/v1/cases/{cid}/bookmarks", json={"event_id": eid, "tags": ["b", "a", "a"]}, headers=a).json()["id"]
    assert c.get(f"/api/v1/cases/{cid}/bookmarks", headers=a).json()[0]["tags"] == ["a", "b"]
    assert c.delete(f"/api/v1/cases/{cid}/bookmarks/{bid}", headers=a).json()["ok"] and c.get(f"/api/v1/cases/{cid}/bookmarks", headers=a).json() == []
    c.post(f"/api/v1/cases/{cid}/notes", json={"target_type": "case", "target_id": cid, "body": "kickoff"}, headers=a)
    assert len(c.get(f"/api/v1/cases/{cid}/notes", params={"target_type": "case", "target_id": cid}, headers=a).json()) == 1
    hid = c.post(f"/api/v1/cases/{cid}/hypotheses", json={"title": "H", "statement": "s"}, headers=a).json()["id"]
    assert c.put(f"/api/v1/cases/{cid}/hypotheses/{hid}", json={"title": "H", "statement": "s", "status": "supported"}, headers=a).json()["status"] == "supported"
    assert c.put(f"/api/v1/cases/{cid}/hypotheses/999", json={"title": "H", "statement": "s"}, headers=a).status_code == 404
    assert len(c.get(f"/api/v1/cases/{cid}/hypotheses", headers=a).json()) == 1
    tid = c.post(f"/api/v1/cases/{cid}/tasks", json={"title": "T"}, headers=a).json()["id"]
    assert c.put(f"/api/v1/cases/{cid}/tasks/{tid}", json={"title": "T", "status": "done"}, headers=a).json()["status"] == "done"
    assert c.put(f"/api/v1/cases/{cid}/tasks/999", json={"title": "T"}, headers=a).status_code == 404
    assert len(c.get(f"/api/v1/cases/{cid}/tasks", headers=a).json()) == 1
    assert c.post(f"/api/v1/cases/{cid}/views", json={"name": "logons", "query": {"text": "4624"}}, headers=a).status_code == 201
    assert c.get(f"/api/v1/cases/{cid}/views", headers=a).json()[0]["name"] == "logons"
    for fmt in ("jsonl", "plaso"):
        r = c.get(f"/api/v1/cases/{cid}/timeline/export", params={"fmt": fmt}, headers=a)
        assert r.status_code == 200 and json.loads(r.text.splitlines()[0])
    assert c.post(f"/api/v1/cases/{cid}/timeline/histogram", params={"bucket": str(10**9)}, json={}, headers=a).json()["bucket_ns"] == 10**9
    assert c.post(f"/api/v1/cases/{cid}/timeline/histogram", json={"text": "nomatch"}, headers=a).json() == {"bucket_ns": 0, "buckets": []}
    for path in ("execution", "users", "provenance", "lateral"):
        assert c.get(f"/api/v1/cases/{cid}/analytics/{path}", headers=a).status_code == 200
    assert c.get(f"/api/v1/cases/{cid}/analytics/provenance", params={"path": "C:\\none"}, headers=a).json() == {}
    fid = c.post(f"/api/v1/cases/{cid}/findings", json={"title": "Manual", "description": "d", "severity": "low", "event_ids": [eid]}, headers=a).json()["id"]
    assert c.get(f"/api/v1/cases/{cid}/findings", params={"state": "proposed"}, headers=a).json()[0]["id"] == fid
    assert c.post(f"/api/v1/cases/{cid}/findings/nope/action", json={"action": "confirm", "text": "long enough text"}, headers=a).status_code == 404
    assert c.post(f"/api/v1/cases/{cid}/findings/{fid}/action", json={"action": "reject", "text": "not supported by data"}, headers=a).json()["state"] == "rejected"
    assert c.post(f"/api/v1/cases/{cid}/findings/{fid}/action", json={"action": "reopen"}, headers=a).json()["state"] == "proposed"
    iid = c.get(f"/api/v1/cases/{cid}/iocs", headers=a).json()
    assert iid == []
    c.post(f"/api/v1/cases/{cid}/iocs", json={"text": "1.2.3.4"}, headers=a)
    first = c.get(f"/api/v1/cases/{cid}/iocs", headers=a).json()[0]["id"]
    assert c.delete(f"/api/v1/cases/{cid}/iocs/{first}", headers=a).json()["ok"]
    assert c.post(f"/api/v1/cases/{cid}/reports", json={"template": "../x"}, headers=a).status_code == 422
    assert c.get(f"/api/v1/cases/{cid}/reports/nope/download", headers=a).status_code == 404
    assert c.post(f"/api/v1/cases/{cid}/custody/anchor", headers=a).json()["seq"] >= 0


@pytest.mark.skipif(not (CORPUS / "evtx" / "System.evtx").exists() or not (BIN / "veritas-artifacts-dump.exe").exists() and not (BIN / "veritas-artifacts-dump").exists(), reason="needs corpus and release binaries")
def test_triage_bundle_and_register_path(env, tmp_path):
    c, app = env
    a = tok(c, "alice")
    cid = c.post("/api/v1/cases", json={"name": "Triage"}, headers=a).json()["id"]
    bundle = tmp_path / "triage.zip"
    files = {"evtx/System.evtx": (CORPUS / "evtx" / "System.evtx").read_bytes(), "prefetch/CMD.EXE-087B4001.pf": (CORPUS / "winprefetch" / "CMD.EXE-087B4001.pf").read_bytes(), "../escape.txt": b"x"}
    with zipfile.ZipFile(bundle, "w") as z:
        for n, d in files.items():
            z.writestr(n, d)
        z.writestr("manifest.json", json.dumps({"files": [{"path": n, "sha256": hashlib.sha256(d).hexdigest()} for n, d in files.items()]}))
    r = c.post(f"/api/v1/cases/{cid}/evidence/register-path", json={"path": str(bundle), "kind": "triage", "expected_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest()}, headers=a)
    assert r.status_code == 201 and r.json()["classified_as"] == "triage"
    assert c.post(f"/api/v1/cases/{cid}/evidence/register-path", json={"path": str(tmp_path / "missing")}, headers=a).status_code == 404
    proc = app.state.processor
    while (nxt := app.state.jobs.next_job()) is not None:
        assert proc.run_job(nxt[0]) == "done"
    job = app.state.jobs.jobs_for_case(cid)[0]
    out = app.state.jobs.step_output(job["job_id"], "triage_bundle")
    assert out["parsed"] == 2 and out["failed"][0]["error"] == "path traversal rejected"
    total = c.post(f"/api/v1/cases/{cid}/timeline/search", json={"include_untimed": True, "limit": 1}, headers=a).json()["total"]
    assert total > 5000
    reproc = c.post(f"/api/v1/cases/{cid}/evidence/{r.json()['id']}/reprocess", headers=a).json()
    assert reproc["job_id"].startswith("J-")
    assert c.get(f"/api/v1/cases/{cid}/evidence/{r.json()['id']}", headers=a).json()["jobs"]


def test_websocket_progress(env):
    c, app = env
    a = tok(c, "alice")
    token = a["Authorization"].split()[1]
    cid = c.post("/api/v1/cases", json={"name": "WS"}, headers=a).json()["id"]
    app.state.jobs.create_job("J-ws", cid, "e" * 64, "file")
    with c.websocket_connect(f"/api/v1/cases/{cid}/ws", subprotocols=[f"veritas.bearer.{token}"]) as ws:
        app.state.hub.publish({"job_id": "J-ws", "step": "verify", "state": "done", "progress": 1.0})
        assert ws.receive_json()["step"] == "verify"
    with pytest.raises(Exception):
        with c.websocket_connect(f"/api/v1/cases/{cid}/ws?access_token=bad") as ws:
            ws.receive_json()
    carol = tok(c, "carol")["Authorization"].split()[1]
    with pytest.raises(Exception):
        with c.websocket_connect(f"/api/v1/cases/{cid}/ws?access_token={carol}") as ws:
            ws.receive_json()


def test_manage_commands(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "m"))
    monkeypatch.setenv("VERITAS_MASTER_KEY", "77" * 32)
    monkeypatch.setenv("VERITAS_ADMIN_PASSWORD", "admin-password-123")
    monkeypatch.setenv("VERITAS_USER_PASSWORD", "short")
    assert manage.main(["create-admin", "--id", "root", "--name", "Root"]) == 0
    assert manage.main(["create-user", "--id", "u1", "--name", "U"]) == 2
    monkeypatch.setenv("VERITAS_USER_PASSWORD", "user-password-123")
    assert manage.main(["create-user", "--id", "u1", "--name", "U"]) == 0
    assert manage.main(["verify-store"]) == 0
    assert manage.main(["verify-audit"]) == 0
    from veritas.api.context import AppContext

    ctx = AppContext(load())
    ctx.create_ledger("C-M", "root")
    assert manage.main(["verify-custody", "C-M"]) == 0
    lp = ctx.settings.ledger_dir / "C-M.jsonl"
    lines = lp.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["purpose"] = "tampered"
    lp.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    assert manage.main(["verify-custody", "C-M"]) == 1
    out = capsys.readouterr().out
    assert "PASS" in out and "FAIL" in out
