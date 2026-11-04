"""API integration tests: RBAC, custody on every evidence access, findings workflow, reports, intake."""
import hashlib
import io
import json
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from veritas.api.auth import hash_password
from veritas.api.config import load
from veritas.api.db import User
from veritas.api.main import create_app
from veritas.timeline.schema import Desc, Event

ROOT = Path(__file__).resolve().parents[3]
PW = "correct horse battery"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "var"))
    monkeypatch.setenv("VERITAS_MASTER_KEY", "22" * 32)
    app = create_app(load(), start_processor=False)
    ctx = app.state.ctx
    with ctx.Session() as s:
        s.add_all([
            User(id="admin", display_name="Admin", password_hash=hash_password(PW), is_admin=True, can_unmask_pii=True),
            User(id="alice", display_name="Alice Examiner", password_hash=hash_password(PW)),
            User(id="bob", display_name="Bob Reviewer", password_hash=hash_password(PW)),
            User(id="eve", display_name="Eve Outsider", password_hash=hash_password(PW)),
        ])
        s.commit()
    with TestClient(app) as c:
        c.app_ctx = ctx
        yield c


def tok(c, user):
    r = c.post("/api/v1/auth/login", json={"username": user, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def make_case(c):
    a = tok(c, "alice")
    case = c.post("/api/v1/cases", json={"name": "Intrusion", "description": "Scope"}, headers=a).json()
    c.post(f"/api/v1/cases/{case['id']}/members", json={"user_id": "bob", "role": "reviewer"}, headers=a)
    return case["id"], a, tok(c, "bob"), tok(c, "eve")


def test_auth_and_rbac(client):
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.post("/api/v1/auth/login", json={"username": "alice", "password": "wrong password"}).status_code == 401
    assert client.get("/api/v1/me").status_code == 401
    assert client.get("/api/v1/me", headers={"Authorization": "Bearer garbage"}).status_code == 401
    cid, a, b, e = make_case(client)
    assert client.get(f"/api/v1/cases/{cid}", headers=e).status_code == 404  # non-member cannot probe
    assert client.get(f"/api/v1/cases/{cid}", headers=b).json()["my_role"] == "reviewer"
    assert client.patch(f"/api/v1/cases/{cid}", json={"status": "review"}, headers=b).status_code == 403
    assert [x["id"] for x in client.get("/api/v1/cases", headers=e).json()] == []
    assert client.get("/api/v1/admin/users", headers=a).status_code == 403
    adm = tok(client, "admin")
    assert len(client.get("/api/v1/admin/users", headers=adm).json()) == 4
    assert client.get(f"/api/v1/cases/{cid}", headers=adm).status_code == 200
    me = client.get("/api/v1/me", headers=a).json()
    assert me["cases"][cid] == "lead" and len(me["signing_key_id"]) == 32


def test_evidence_custody_and_verifier(client):
    cid, a, b, e = make_case(client)
    data = b"MZ" + bytes(range(256)) * 40
    r = client.post(f"/api/v1/cases/{cid}/evidence", files={"file": ("tool.exe", io.BytesIO(data))}, data={"kind": "file", "expected_sha256": hashlib.sha256(data).hexdigest()}, headers=a)
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["sha256"] == hashlib.sha256(data).hexdigest() and ev["classified_as"] == "pe" and ev["job_id"].startswith("J-")
    assert client.post(f"/api/v1/cases/{cid}/evidence", files={"file": ("x", io.BytesIO(b"x"))}, headers=e).status_code == 404  # non-member
    client.post(f"/api/v1/cases/{cid}/members", json={"user_id": "eve", "role": "viewer"}, headers=a)
    assert client.post(f"/api/v1/cases/{cid}/evidence", files={"file": ("x", io.BytesIO(b"x"))}, headers=e).status_code == 403  # viewer below examiner
    assert client.get(f"/api/v1/cases/{cid}/evidence/{ev['id']}/bytes", headers=e).status_code == 403
    bad = client.post(f"/api/v1/cases/{cid}/evidence", files={"file": ("y", io.BytesIO(b"yy"))}, data={"expected_sha256": "0" * 64}, headers=a)
    assert bad.status_code == 409
    hexv = client.get(f"/api/v1/cases/{cid}/evidence/{ev['id']}/bytes", params={"offset": 2, "length": 4}, headers=a).json()
    assert hexv["hex"] == "00010203"
    assert client.post(f"/api/v1/cases/{cid}/evidence/{ev['id']}/verify", headers=a).json()["ok"]
    dl = client.get(f"/api/v1/cases/{cid}/evidence/{ev['id']}/download", params={"reason": "court copy"}, headers=a)
    assert dl.content == data
    entries = client.get(f"/api/v1/cases/{cid}/custody", headers=a).json()["entries"]
    kinds = [x["kind"] for x in entries]
    assert kinds[0] == "genesis" and "ingest" in kinds and kinds.count("access") >= 2 and "export" in kinds
    assert client.get(f"/api/v1/cases/{cid}/custody/verify", headers=b).json()["verdict"] == "PASS"
    export = client.get(f"/api/v1/cases/{cid}/custody/export", headers=a)
    assert export.status_code == 200
    verifier = next((p for p in [ROOT / "target" / d / f"veritas-verify{x}" for d in ("release", "debug") for x in (".exe", "")] if p.exists()), None)
    if verifier:
        path = Path(client.app_ctx.settings.data_dir) / "export.json"
        path.write_bytes(export.content)
        out = subprocess.run([str(verifier), "export", str(path)], capture_output=True, text=True)
        assert out.returncode == 0 and out.stdout.strip().endswith("PASS"), out.stdout


def seed_events(client, cid, sha):
    evs = [
        Event(data_type="windows:evtx:record", timestamp_desc=Desc.EVENT, message="[4624] logon from 10.0.0.5 by bob@example.com", timestamp=1_700_000_000_000_000_000 + i * 10**9, evidence_sha256=sha,
              evidence_path="Security.evtx", offset=i, parser="evtx", parser_version="0.1.0", host="WS01",
              attrs={"event_identifier": 4624, "logon_type": "10", "ip_address": "10.0.0.5", "target_user_name": "admin", "channel": "Security", "source_name": "Microsoft-Windows-Security-Auditing"})
        for i in range(5)
    ]
    client.app_ctx.timeline.ingest(cid, evs)


def test_timeline_findings_reports(client):
    cid, a, b, e = make_case(client)
    data = b"evidence-bytes" * 100
    ev = client.post(f"/api/v1/cases/{cid}/evidence", files={"file": ("Security.evtx", io.BytesIO(data))}, headers=a).json()
    seed_events(client, cid, ev["sha256"])
    res = client.post(f"/api/v1/cases/{cid}/timeline/search", json={"text": "logon"}, headers=b).json()
    assert res["total"] == 5 and "bob@example.com" not in json.dumps(res) and "[EMAIL:" in res["events"][0]["message"]
    assert client.post(f"/api/v1/cases/{cid}/timeline/search", json={"text": "logon", "unmask": True}, headers=a).status_code == 403
    adm = tok(client, "admin")
    assert "bob@example.com" in client.post(f"/api/v1/cases/{cid}/timeline/search", json={"text": "logon", "unmask": True}, headers=adm).text
    hist = client.post(f"/api/v1/cases/{cid}/timeline/histogram", json={}, headers=b).json()
    assert sum(x["count"] for x in hist["buckets"]) == 5
    facets = client.post(f"/api/v1/cases/{cid}/timeline/facets/data_type", json={}, headers=b).json()
    assert facets == [{"value": "windows:evtx:record", "count": 5}]
    assert client.post(f"/api/v1/cases/{cid}/timeline/facets/attrs", json={}, headers=b).status_code == 400
    eid = res["events"][0]["id"]
    assert client.post(f"/api/v1/cases/{cid}/bookmarks", json={"event_id": eid, "label": "first logon", "tags": ["rdp"]}, headers=a).status_code == 201
    assert client.post(f"/api/v1/cases/{cid}/bookmarks", json={"event_id": eid}, headers=b).status_code == 201
    assert client.post(f"/api/v1/cases/{cid}/hypotheses", json={"title": "RDP", "statement": "attacker used RDP", "supporting_event_ids": [eid]}, headers=a).status_code == 201
    assert client.post(f"/api/v1/cases/{cid}/tasks", json={"title": "check firewall", "assignee": "eve"}, headers=a).status_code == 422
    assert client.post(f"/api/v1/cases/{cid}/tasks", json={"title": "check firewall", "assignee": "bob"}, headers=a).status_code == 201
    assert client.post(f"/api/v1/cases/{cid}/notes", json={"target_type": "event", "target_id": str(eid), "body": "interesting"}, headers=a).status_code == 201
    exp = client.get(f"/api/v1/cases/{cid}/timeline/export", params={"fmt": "csv"}, headers=a)
    assert exp.status_code == 200 and exp.headers["X-Content-SHA256"] == hashlib.sha256(exp.content).hexdigest()

    # Findings: rules propose; examiner confirms; same person cannot approve; reviewer approves.
    assert client.post(f"/api/v1/cases/{cid}/findings/run", headers=a).json()["proposed"] >= 1
    fl = client.get(f"/api/v1/cases/{cid}/findings", headers=a).json()
    lat = next(f for f in fl if f["rule"] == "lateral_movement")
    assert lat["state"] == "proposed"
    url = f"/api/v1/cases/{cid}/findings/{lat['id']}/action"
    assert client.post(url, json={"action": "approve", "text": "x"}, headers=b).status_code == 409
    assert client.post(url, json={"action": "confirm", "text": "short"}, headers=a).status_code == 422
    assert client.post(url, json={"action": "confirm", "text": "RDP logons from external host confirmed"}, headers=a).json()["state"] == "confirmed"
    assert client.post(url, json={"action": "approve", "text": "self"}, headers=a).status_code == 403
    assert client.post(url, json={"action": "approve", "text": "reviewed artifacts"}, headers=b).json()["state"] == "approved"
    # Re-running rules never resets a human decision.
    client.post(f"/api/v1/cases/{cid}/findings/run", headers=a)
    assert next(f for f in client.get(f"/api/v1/cases/{cid}/findings", headers=a).json() if f["id"] == lat["id"])["state"] == "approved"

    # Reports: deterministic for unchanged case state, signed, recorded in custody.
    r1 = client.post(f"/api/v1/cases/{cid}/reports", json={"format": "pdf"}, headers=a).json()
    r1b = client.post(f"/api/v1/cases/{cid}/reports", json={"format": "pdf"}, headers=a).json()
    assert r1["state_hash"] != r1b["state_hash"] or r1["report_sha256"] == r1b["report_sha256"]
    pdf = client.get(f"/api/v1/cases/{cid}/reports/{r1['id']}/download", headers=b)
    assert pdf.content.startswith(b"%PDF") and hashlib.sha256(pdf.content).hexdigest() == r1["report_sha256"]
    sig = client.get(f"/api/v1/cases/{cid}/reports/{r1['id']}/download", params={"part": "signature"}, headers=b).json()
    from nacl.signing import VerifyKey

    VerifyKey(bytes.fromhex(sig["signer_public_key"])).verify(bytes.fromhex(sig["report_sha256"]), bytes.fromhex(sig["signature_ed25519"]))
    docx = client.post(f"/api/v1/cases/{cid}/reports", json={"format": "docx"}, headers=a).json()
    assert docx["format"] == "docx" and len(client.get(f"/api/v1/cases/{cid}/reports", headers=a).json()) >= 2
    assert client.get(f"/api/v1/cases/{cid}/custody/verify", headers=a).json()["verdict"] == "PASS"
    assert client.get(f"/api/v1/cases/{cid}/analytics/lateral", headers=b).json()["edges"][0]["src"] == "10.0.0.5"

    # IOCs
    assert client.post(f"/api/v1/cases/{cid}/iocs", json={"text": "10.0.0.5\nevil.example"}, headers=a).json()["added"] == 2
    sw = client.post(f"/api/v1/cases/{cid}/iocs/sweep", headers=a).json()
    assert sw["by_ioc"].get("ipv4:10.0.0.5", 0) >= 5
    stix = client.get(f"/api/v1/cases/{cid}/iocs/stix", headers=b).json()
    assert stix["type"] == "bundle" and any(o["type"] == "indicator" for o in stix["objects"])
    assert client.post(f"/api/v1/cases/{cid}/iocs", json={"text": "regex:(a+)+"}, headers=a).status_code == 422

    # Audit trail: every request by a principal is recorded and the chain verifies.
    adm = tok(client, "admin")
    assert client.get("/api/v1/admin/audit/verify", headers=adm).json()["ok"]
    acts = client.get(f"/api/v1/cases/{cid}/activity", headers=a).json()
    assert any("timeline/search" in r["action"] for r in acts) and any(r["actor"] == "bob" for r in acts)


def test_intake_resumable(client):
    cid, a, b, e = make_case(client)
    segs = [b"A" * 1000, b"B" * 1000, b"C" * 7]
    whole = b"".join(segs)
    manifest = {"evidence_name": "disk.raw", "kind": "disk", "total_size": len(whole), "sha256": hashlib.sha256(whole).hexdigest(),
                "segments": [{"index": i, "size": len(s), "sha256": hashlib.sha256(s).hexdigest()} for i, s in enumerate(segs)], "host": "WS01"}
    sid = client.post("/api/v1/intake/sessions", params={"case_id": cid}, json=manifest, headers=a).json()["session_id"]
    put = lambda i, body, h=None: client.put(f"/api/v1/intake/sessions/{sid}/segments/{i}", content=body, headers={**a, "X-Segment-SHA256": h or hashlib.sha256(segs[i]).hexdigest()})
    assert put(0, segs[0]).status_code == 200
    assert put(1, b"tampered" + segs[1][8:]).status_code == 422
    assert put(1, segs[1], "f" * 64).status_code == 409
    assert client.post(f"/api/v1/intake/sessions/{sid}/complete", headers=a).status_code == 409
    assert client.get(f"/api/v1/intake/sessions/{sid}", headers=a).json()["present"] == [0]
    assert client.get(f"/api/v1/intake/sessions/{sid}", headers=e).status_code == 404
    assert put(1, segs[1]).status_code == 200 and put(2, segs[2]).status_code == 200
    done = client.post(f"/api/v1/intake/sessions/{sid}/complete", headers=a)
    assert done.status_code == 201 and done.json()["sha256"] == manifest["sha256"]


def test_metrics_and_headers(client):
    r = client.get("/metrics")
    assert r.status_code == 200 and b"veritas_queue_depth" in r.content
    assert r.headers["X-Frame-Options"] == "DENY"
