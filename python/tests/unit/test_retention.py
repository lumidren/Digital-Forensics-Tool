"""Retention disposal: refusal rules, two-step token, shared objects, destruction and retained proof."""
import hashlib
import io
import json
import os
import stat
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from veritas.api.auth import hash_password
from veritas.api.config import load
from veritas.api.db import Bookmark, Case, Evidence, Membership, Note, User
from veritas.api.main import create_app
from veritas.timeline.schema import Desc, Event

ROOT = Path(__file__).resolve().parents[3]
PW = "correct horse battery"
DISPOSE = "/api/v1/admin/retention/dispose"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "var"))
    monkeypatch.setenv("VERITAS_MASTER_KEY", "33" * 32)
    app = create_app(load(), start_processor=False)
    ctx = app.state.ctx
    with ctx.Session() as s:
        s.add_all([
            User(id="admin", display_name="Admin", password_hash=hash_password(PW), is_admin=True, can_unmask_pii=True),
            User(id="alice", display_name="Alice Lead", password_hash=hash_password(PW)),
            User(id="bob", display_name="Bob Examiner", password_hash=hash_password(PW)),
        ])
        s.commit()
    with TestClient(app) as c:
        c.app_ctx = ctx
        yield c


def tok(c, user):
    r = c.post("/api/v1/auth/login", json={"username": user, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def upload(c, cid, h, data, name="file.bin"):
    r = c.post(f"/api/v1/cases/{cid}/evidence", files={"file": (name, io.BytesIO(data))}, data={"kind": "file"}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


def expire(c, cid, days=1):
    with c.app_ctx.Session() as s:
        s.get(Case, cid).retention_until = datetime.now(timezone.utc) - timedelta(days=days)
        s.commit()


def make_case(c, a, data=b"evidence-bytes" * 300, events=5):
    cid = c.post("/api/v1/cases", json={"name": "Old matter"}, headers=a).json()["id"]
    c.post(f"/api/v1/cases/{cid}/members", json={"user_id": "bob", "role": "examiner"}, headers=a)
    ev = upload(c, cid, a, data, "Security.evtx")
    c.app_ctx.timeline.ingest(cid, [
        Event(data_type="windows:evtx:record", timestamp_desc=Desc.EVENT, message=f"logon {i}", timestamp=1_700_000_000_000_000_000 + i * 10**9, evidence_sha256=ev["sha256"],
              evidence_path="Security.evtx", offset=i, parser="evtx", parser_version="0.1.0", host="WS01", attrs={"event_identifier": 4624})
        for i in range(events)
    ])
    return cid, ev


def dry(c, adm, ids, reason="retention period elapsed"):
    return c.post(DISPOSE, json={"case_ids": ids, "reason": reason}, headers=adm)


def real(c, adm, ids, token, reason="retention period elapsed", confirm=None):
    body = {"case_ids": ids, "reason": reason, "token": token, "confirm": confirm if confirm is not None else [f"DISPOSE {i}" for i in ids]}
    return c.post(DISPOSE, params={"dry_run": "false"}, json=body, headers=adm)


def verifier():
    return next((p for p in [ROOT / "target" / d / f"veritas-verify{x}" for d in ("release", "debug") for x in (".exe", "")] if p.exists()), None)


def test_non_admin_forbidden(client):
    a = tok(client, "alice")
    cid, _ = make_case(client, a)
    expire(client, cid)
    assert dry(client, a, [cid]).status_code == 403
    assert real(client, a, [cid], "x").status_code == 403
    assert client.post("/api/v1/admin/retention/sweep", headers=a).status_code == 403


def test_legal_hold_and_retention_block(client):
    a, adm = tok(client, "alice"), tok(client, "admin")
    held, _ = make_case(client, a)
    future, _ = make_case(client, a, b"other" * 50)
    undated, _ = make_case(client, a, b"third" * 50)
    expire(client, held)
    assert client.patch(f"/api/v1/cases/{held}", json={"legal_hold": True}, headers=a).status_code == 200
    with client.app_ctx.Session() as s:
        s.get(Case, undated).retention_until = None
        s.commit()
    for cid, why in ((held, "legal hold"), (future, "retention period runs until"), (undated, "no retention date")):
        r = dry(client, adm, [cid])
        assert r.status_code == 409, r.text
        assert why in r.json()["detail"]["refused"][0]["reason"]
    # one refused case refuses the whole request; the sweep lists none of them
    r = dry(client, adm, [future, held])
    assert r.status_code == 409 and len(r.json()["detail"]["refused"]) == 2
    assert dry(client, adm, ["C-NOPE"]).status_code == 409
    assert client.post("/api/v1/admin/retention/sweep", headers=adm).json()["due_for_disposal"] == []


def test_dry_run_lists_exact_objects(client):
    a, adm = tok(client, "alice"), tok(client, "admin")
    d1, d2 = b"first-object" * 100, b"second-object" * 77
    cid, ev1 = make_case(client, a, d1, events=7)
    ev2 = upload(client, cid, a, d2, "mem.raw")
    client.post(f"/api/v1/cases/{cid}/notes", json={"target_type": "case", "target_id": cid, "body": "n"}, headers=a)
    expire(client, cid)
    assert client.post("/api/v1/admin/retention/sweep", headers=adm).json()["due_for_disposal"] == [cid]
    r = dry(client, adm, [cid])
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan["dry_run"] is True and plan["confirm_phrases"] == [f"DISPOSE {cid}"] and plan["confirmation_token"]
    cp = plan["cases"][0]
    objs = {o["address"]: o for o in cp["evidence_objects"]}
    assert set(objs) == {hashlib.sha256(d1).hexdigest(), hashlib.sha256(d2).hexdigest()}
    assert objs[ev1["sha256"]]["size"] == len(d1) and objs[ev1["sha256"]]["md5"] == hashlib.md5(d1).hexdigest()  # noqa: S324
    assert objs[ev2["sha256"]]["sha3_256"] == hashlib.sha3_256(d2).hexdigest() and objs[ev2["sha256"]]["evidence_id"] == ev2["id"]
    assert cp["timeline_events"] == 7 and cp["kept_shared"] == [] and cp["derived_objects"] == []
    assert cp["db_rows"]["evidence"] == 2 and cp["db_rows"]["notes"] == 1 and cp["db_rows"]["memberships"] == 1 and cp["memberships_kept"] == ["alice"]
    assert cp["bytes"] == len(d1) + len(d2) and len(cp["pending_jobs"]) == 2
    # nothing was deleted by the dry run, and it was audited
    assert client.app_ctx.store.exists(ev1["sha256"]) and client.app_ctx.timeline.count(cid) == 7
    assert any(r.action == "retention.dispose.dry_run" for r in client.app_ctx.audit.rows(case_id=cid))
    # the plan hash is stable while nothing changes
    assert dry(client, adm, [cid]).json()["plan_sha256"] == plan["plan_sha256"]


def test_token_required_and_bound_to_plan(client):
    a, adm = tok(client, "alice"), tok(client, "admin")
    cid, ev = make_case(client, a)
    expire(client, cid)
    plan = dry(client, adm, [cid]).json()
    token = plan["confirmation_token"]
    assert real(client, adm, [cid], None).status_code == 403
    assert real(client, adm, [cid], "garbage").status_code == 403
    exp, mac = token.split(".")
    tampered = f"{exp}.{('0' if mac[0] != '0' else '1') + mac[1:]}"
    assert real(client, adm, [cid], tampered).status_code == 403
    assert real(client, adm, [cid], f"{int(exp) + 3600}.{mac}").status_code == 403  # extending the expiry breaks the MAC
    assert real(client, adm, [cid], token, reason="a different reason").status_code == 403
    assert real(client, adm, [cid], token, confirm=["DISPOSE C-OTHER"]).status_code == 422
    ctx = client.app_ctx
    stale, _ = ctx.disposal_token("admin", [cid], plan["plan_sha256"], "retention period elapsed", now=time.time() - 2 * ctx.disposal_token_ttl_s)
    r = real(client, adm, [cid], stale)
    assert r.status_code == 403 and "expired" in r.json()["detail"]
    # the plan changes (new evidence) after the dry run: the old token no longer matches
    upload(client, cid, a, b"late arrival" * 10)
    r = real(client, adm, [cid], token)
    assert r.status_code == 403 and "does not match" in r.json()["detail"]
    # another admin cannot reuse the token
    with ctx.Session() as s:
        s.add(User(id="admin2", display_name="Admin 2", password_hash=hash_password(PW), is_admin=True))
        s.commit()
    fresh = dry(client, adm, [cid]).json()["confirmation_token"]
    assert real(client, tok(client, "admin2"), [cid], fresh).status_code == 403
    assert ctx.store.exists(ev["sha256"]) and ctx.timeline.count(cid) == 5
    assert real(client, adm, [cid], fresh).status_code == 200


def test_shared_object_is_kept(client):
    a, adm = tok(client, "alice"), tok(client, "admin")
    shared = b"same image in two cases" * 64
    old, ev_old = make_case(client, a, shared)
    own = upload(client, old, a, b"only in the old case" * 20)
    live, ev_live = make_case(client, a, shared)
    assert ev_old["sha256"] == ev_live["sha256"]
    expire(client, old)
    plan = dry(client, adm, [old]).json()
    cp = plan["cases"][0]
    assert [k["address"] for k in cp["kept_shared"]] == [ev_old["sha256"]] and cp["kept_shared"][0]["referenced_by"] == [live]
    assert [o["address"] for o in cp["evidence_objects"]] == [own["sha256"]]
    res = real(client, adm, [old], plan["confirmation_token"]).json()["disposed"][0]
    assert res["kept_shared"] == [ev_old["sha256"]] and res["objects_deleted"] == [own["sha256"]]
    ctx = client.app_ctx
    assert ctx.store.exists(ev_live["sha256"]) and not ctx.store.exists(own["sha256"])
    hexv = client.get(f"/api/v1/cases/{live}/evidence/{ev_live['id']}/bytes", params={"length": 8}, headers=a)
    assert hexv.status_code == 200 and hexv.json()["hex"] == shared[:8].hex()
    assert ctx.timeline.count(live) == 5 and ctx.timeline.count(old) == 0


def test_disposal_destroys_and_keeps_proof(client):
    a, b, adm = tok(client, "alice"), tok(client, "bob"), tok(client, "admin")
    ctx = client.app_ctx
    data = b"to be destroyed" * 500
    cid, ev = make_case(client, a, data, events=4)
    eid = client.post(f"/api/v1/cases/{cid}/timeline/search", json={}, headers=a).json()["events"][0]["id"]
    client.post(f"/api/v1/cases/{cid}/bookmarks", json={"event_id": eid, "label": "x"}, headers=b)
    client.post(f"/api/v1/cases/{cid}/notes", json={"target_type": "case", "target_id": cid, "body": "note"}, headers=b)
    client.post(f"/api/v1/cases/{cid}/hypotheses", json={"title": "h", "statement": "s"}, headers=b)
    client.post(f"/api/v1/cases/{cid}/tasks", json={"title": "t"}, headers=b)
    client.post(f"/api/v1/cases/{cid}/iocs", json={"text": "10.0.0.5"}, headers=b)
    client.post(f"/api/v1/cases/{cid}/views", json={"name": "v", "query": {}}, headers=b)
    client.post(f"/api/v1/cases/{cid}/findings", json={"title": "f", "description": "d", "severity": "low"}, headers=b)
    # a read-only report file (as written by a WORM-style copy) and an intake leftover
    rdir = ctx.settings.reports_dir / cid
    rdir.mkdir(parents=True)
    rep = rdir / ("ab" * 32 + ".pdf")
    rep.write_bytes(b"%PDF-1.7 fake")
    os.chmod(rep, stat.S_IREAD)
    seg = b"partial upload"
    sid = client.post("/api/v1/intake/sessions", params={"case_id": cid}, json={"evidence_name": "x.E01", "total_size": 99, "sha256": "0" * 64,
                                                                               "segments": [{"index": 0, "size": len(seg), "sha256": hashlib.sha256(seg).hexdigest()}]}, headers=a).json()["session_id"]
    client.put(f"/api/v1/intake/sessions/{sid}/segments/0", content=seg, headers={**a, "X-Segment-SHA256": hashlib.sha256(seg).hexdigest()})
    obj_path, meta_path = ctx.store._obj(ev["sha256"]), ctx.store._meta(ev["sha256"])
    assert obj_path.exists() and not os.access(obj_path, os.W_OK)  # WORM: read-only on disk
    ledger_path = ctx.settings.ledger_dir / f"{cid}.jsonl"
    expire(client, cid)

    plan = dry(client, adm, [cid]).json()
    cp = plan["cases"][0]
    assert [f["file"] for f in cp["report_files"]] == [rep.name] and [i["session_id"] for i in cp["intake_sessions"]] == [sid]
    r = real(client, adm, [cid], plan["confirmation_token"])
    assert r.status_code == 200, r.text
    res = r.json()["disposed"][0]
    assert res["objects_deleted"] == [ev["sha256"]] and res["retained_by_object_lock"] == [] and res["timeline_events_deleted"] == 4
    assert len(res["anchors"]) == 2

    # destroyed: store object + meta (read-only files, also on Windows), timeline, reports, intake, DB rows
    assert not obj_path.exists() and not meta_path.exists() and not ctx.store.exists(ev["sha256"])
    assert ctx.timeline.count(cid) == 0 and not rdir.exists() and not (ctx.settings.data_dir / "intake" / sid).exists()
    from veritas.api.db import FindingRow, Hypothesis, IocRow, Report, SavedView, Task
    with ctx.Session() as s:
        for model in (Evidence, FindingRow, Bookmark, Note, Hypothesis, Task, IocRow, SavedView, Report):
            assert s.query(model).filter_by(case_id=cid).count() == 0, model
        assert [m.user_id for m in s.query(Membership).filter_by(case_id=cid)] == ["alice"]
        c = s.get(Case, cid)
        assert c.status == "disposed" and c.disposed_by == "admin" and c.disposal_reason == "retention period elapsed" and c.disposed_at is not None

    # retained: ledger with the signed intent listing every address and hash, anchors, audit log
    assert ledger_path.exists()
    entries = client.get(f"/api/v1/cases/{cid}/custody", headers=a).json()["entries"]
    notes = [e for e in entries if e["kind"] == "note" and e["purpose"] == "retention disposal"]
    assert [n["details"]["phase"] for n in notes] == ["intent", "completed"]
    assert notes[0]["details"]["objects"][0] == {"address": ev["sha256"], "sha256": ev["sha256"], "md5": hashlib.md5(data).hexdigest(),  # noqa: S324
                                                 "sha3_256": hashlib.sha3_256(data).hexdigest(), "size": len(data), "evidence_id": ev["id"], "class": "evidence"}
    anchors = ctx.anchors(cid)
    assert anchors[-1]["head_hash"] == entries[-1]["entry_hash"] and anchors[-2]["head_hash"] == notes[0]["entry_hash"]
    v = client.get(f"/api/v1/cases/{cid}/custody/verify", headers=a).json()
    assert v["verdict"] == "PASS"
    assert client.get(f"/api/v1/cases/{cid}/custody/verify", headers=adm).json()["verdict"] == "PASS"
    acts = [r.action for r in ctx.audit.rows(case_id=cid, limit=5000)]
    assert "retention.dispose" in acts and "retention.dispose.dry_run" in acts
    row = next(r for r in ctx.audit.rows(case_id=cid, limit=5000) if r.action == "retention.dispose")
    assert row.detail["bytes"] == cp["bytes"] == len(data) + len(b"%PDF-1.7 fake") + cp["intake_sessions"][0]["bytes"] and cp["intake_sessions"][0]["bytes"] > len(seg) and row.detail["reason"] == "retention period elapsed"
    assert client.get("/api/v1/admin/audit/verify", headers=adm).json()["ok"]
    export = client.get(f"/api/v1/cases/{cid}/custody/export", headers=a)
    assert export.status_code == 200
    vbin = verifier()
    if vbin:
        path = ctx.settings.data_dir / "disposed-export.json"
        path.write_bytes(export.content)
        out = subprocess.run([str(vbin), "export", str(path)], capture_output=True, text=True)
        assert out.returncode == 0 and out.stdout.strip().endswith("PASS"), out.stdout + out.stderr

    # read-only: mutations 409, evidence 410, reads still work
    assert client.get(f"/api/v1/cases/{cid}", headers=a).json()["status"] == "disposed"
    assert client.patch(f"/api/v1/cases/{cid}", json={"name": "x"}, headers=a).status_code == 409
    assert client.patch(f"/api/v1/cases/{cid}", json={"legal_hold": True}, headers=adm).status_code == 409
    assert client.post(f"/api/v1/cases/{cid}/notes", json={"target_type": "case", "target_id": cid, "body": "n"}, headers=a).status_code == 409
    assert client.post(f"/api/v1/cases/{cid}/members", json={"user_id": "bob", "role": "viewer"}, headers=a).status_code == 409
    assert client.post(f"/api/v1/cases/{cid}/findings/run", headers=a).status_code == 409
    assert client.post(f"/api/v1/cases/{cid}/reports", json={}, headers=a).status_code == 409
    assert client.post("/api/v1/intake/sessions", params={"case_id": cid}, json={"evidence_name": "y", "total_size": 1, "sha256": "0" * 64, "segments": []}, headers=a).status_code == 409
    assert client.get(f"/api/v1/cases/{cid}/evidence", headers=a).status_code == 410
    assert client.get(f"/api/v1/cases/{cid}/evidence/{ev['id']}", headers=a).status_code == 410
    assert client.get(f"/api/v1/cases/{cid}/evidence/{ev['id']}/bytes", headers=adm).status_code == 410
    assert client.post(f"/api/v1/cases/{cid}/evidence", files={"file": ("z", io.BytesIO(b"z"))}, headers=a).status_code == 410
    assert client.post(f"/api/v1/cases/{cid}/timeline/search", json={}, headers=a).json()["total"] == 0
    assert client.get(f"/api/v1/cases/{cid}/custody", headers=b).status_code == 404  # non-lead membership removed
    # cannot dispose twice; no longer due
    assert dry(client, adm, [cid]).status_code == 409
    assert cid not in client.post("/api/v1/admin/retention/sweep", headers=adm).json()["due_for_disposal"]


def test_store_delete_clears_readonly(tmp_path):
    from veritas.store.content import LocalStore

    st = LocalStore(tmp_path / "s")
    m = st.put("C-1", io.BytesIO(b"abc"))
    p = st._obj(m.address)
    assert not os.access(p, os.W_OK)
    assert st.delete(m.address) == "deleted" and not p.exists() and not st._meta(m.address).exists()
    assert st.delete(m.address) == "missing"
    with pytest.raises(Exception):
        st.delete("../../etc")


def test_s3_delete_reports_object_lock():
    pytest.importorskip("boto3")
    from veritas.store.content import S3Store

    class Denied(Exception):
        response = {"Error": {"Code": "AccessDenied"}}

    class Pager:
        def paginate(self, Bucket, Prefix):
            yield {"Versions": [{"Key": Prefix, "VersionId": "v1"}]}

    class Client:
        def __init__(self, refuse, lock_until=None):
            self.refuse, self.lock_until, self.deleted = refuse, lock_until, []

        def get_object_lock_configuration(self, Bucket):
            return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

        def get_paginator(self, name):
            return Pager()

        def get_object_retention(self, Bucket, Key, VersionId=None):
            return {"Retention": {"Mode": "COMPLIANCE", "RetainUntilDate": self.lock_until}} if self.lock_until else {}

        def get_object_legal_hold(self, Bucket, Key, VersionId=None):
            return {"LegalHold": {"Status": "OFF"}}

        def delete_object(self, Bucket, Key, VersionId):
            if self.refuse:
                raise Denied()
            self.deleted.append((Key, VersionId))

    a = "a" * 64
    assert S3Store("b", client=Client(True, datetime.now(timezone.utc) + timedelta(days=30))).delete(a) == "retained_by_object_lock"
    assert S3Store("b", client=Client(True)).delete(a) == "delete_denied"
    c = Client(False)
    assert S3Store("b", client=c).delete(a) == "deleted" and len(c.deleted) == 2


def test_existing_db_gets_disposal_columns(tmp_path):
    import sqlite3

    from veritas.api.db import make_engine

    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cases (id VARCHAR(64) PRIMARY KEY, name VARCHAR(300), description TEXT, status VARCHAR(32), created_by VARCHAR(64), created DATETIME, "
                "timezone VARCHAR(64), legal_hold BOOLEAN, retention_until DATETIME, ledger_id VARCHAR(64))")
    con.commit()
    con.close()
    make_engine(f"sqlite:///{db.as_posix()}").dispose()
    cols = {r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(cases)")}
    assert {"disposed_at", "disposed_by", "disposal_reason"} <= cols
    assert json.dumps(sorted(cols))
