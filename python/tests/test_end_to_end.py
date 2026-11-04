"""End-to-end: evidence in through the API, real parsers in sandboxed workers, timeline, findings,
signed report, custody export verified by the Rust verifier. Native profile, no containers.

Requires the reference corpus (testdata/fetch.py) and release binaries (cargo build --release).
"""
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

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "testdata" / "corpus"
BIN = ROOT / "target" / "release"
EXE = ".exe" if (BIN / "fs-tool.exe").exists() else ""
PW = "end-to-end-password"

SAMPLES = [
    ("plaso/evtx/System.evtx", "logs", "evtx", 1000),
    ("plaso/winprefetch/CMD.EXE-087B4001.pf", "file", "prefetch", 1),
    ("plaso/SYSTEM", "file", "regf-events", 1000),
    ("plaso/NTUSER.DAT", "file", "regf-events", 100),
    ("plaso/MFT", "file", "mft", 1000),  # raw $MFT detected by its FILE0 record signature
    ("plaso/chrome/History", "file", "auto", 10),
    ("plaso/test.pcap", "pcap", "pcap", 10),
    ("plaso/syslog/syslog", "logs", "auto", 5),
    ("dfvfs/ntfs.raw", "disk", "disk", 10),
]

pytestmark = pytest.mark.skipif(not (CORPUS / "plaso" / "SYSTEM").exists() or not (BIN / f"fs-tool{EXE}").exists(), reason="needs corpus and release binaries")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "var"))
    monkeypatch.setenv("VERITAS_MASTER_KEY", "44" * 32)
    monkeypatch.setenv("VERITAS_BIN_DIR", str(BIN))
    app = create_app(load(), start_processor=False)
    ctx = app.state.ctx
    with ctx.Session() as s:
        s.add_all([User(id="alice", display_name="Alice", password_hash=hash_password(PW)), User(id="bob", display_name="Bob", password_hash=hash_password(PW))])
        s.commit()
    with TestClient(app) as c:
        yield c, app


def login(c, u):
    return {"Authorization": "Bearer " + c.post("/api/v1/auth/login", json={"username": u, "password": PW}).json()["access_token"]}


def test_pipeline_end_to_end(env):
    c, app = env
    a, b = login(c, "alice"), login(c, "bob")
    cid = c.post("/api/v1/cases", json={"name": "E2E", "description": "corpus run"}, headers=a).json()["id"]
    c.post(f"/api/v1/cases/{cid}/members", json={"user_id": "bob", "role": "reviewer"}, headers=a)
    jobs = []
    for rel, kind, expect_class, _ in SAMPLES:
        data = (CORPUS / rel).read_bytes()
        r = c.post(f"/api/v1/cases/{cid}/evidence", files={"file": (Path(rel).name, io.BytesIO(data))}, data={"kind": kind, "expected_sha256": hashlib.sha256(data).hexdigest()}, headers=a)
        assert r.status_code == 201, r.text
        ev = r.json()
        assert ev["classified_as"] == expect_class, (rel, ev["classified_as"])
        jobs.append(ev["job_id"])
    proc = app.state.processor
    states = {}
    while (nxt := app.state.jobs.next_job()) is not None:
        states[nxt[0]] = proc.run_job(nxt[0])
    failed = {j: app.state.jobs.job(j) for j, s in states.items() if s != "done" and j in jobs}
    assert not failed, json.dumps(failed, indent=1)[:4000]

    search = lambda body: c.post(f"/api/v1/cases/{cid}/timeline/search", json={**body, "limit": 1}, headers=b).json()["total"]
    total = search({"include_untimed": True})
    assert total > 20000
    for dt in ("windows:evtx:record", "windows:prefetch:execution", "windows:registry:key_value", "fs:stat:ntfs", "chrome:history:page_visited", "syslog:line"):
        assert search({"data_types": [dt]}) > 0, dt
    assert search({"text": "CMD.EXE"}) > 0

    findings = c.get(f"/api/v1/cases/{cid}/findings", headers=a).json()
    assert findings and all(f["state"] == "proposed" for f in findings)
    assert any(f["rule"] == "timestomp" for f in findings)

    custody = c.get(f"/api/v1/cases/{cid}/custody", headers=a).json()["entries"]
    kinds = [e["kind"] for e in custody]
    assert kinds.count("ingest") == len(SAMPLES) and kinds.count("access") >= len(SAMPLES)
    # The dfvfs NTFS test image holds no Windows artifacts, so harvest runs and extracts nothing;
    # every artifact it did extract would appear as a signed transform entry.
    disk_job = jobs[[s[0] for s in SAMPLES].index("dfvfs/ntfs.raw")]
    harvest = app.state.jobs.step_output(disk_job, "harvest")
    assert harvest["artifacts"] == harvest["stored"] == kinds.count("transform") == 2 and not harvest["failed"]  # $MFT and $LogFile
    assert harvest["preserved_only"] == 1 and harvest["parsed"] == 1
    # This volume's $LogFile was never written (all 0xFF), so it parses to zero records.
    assert search({"data_types": ["fs:ntfs:logfile"], "include_untimed": True}) == 0
    assert app.state.jobs.step_output(disk_job, "fs_timeline")["events"] > 0

    f = findings[0]
    c.post(f"/api/v1/cases/{cid}/findings/{f['id']}/action", json={"action": "confirm", "text": "reviewed supporting artifacts"}, headers=a)
    c.post(f"/api/v1/cases/{cid}/findings/{f['id']}/action", json={"action": "approve", "text": "independent review done"}, headers=b)
    rep1 = c.post(f"/api/v1/cases/{cid}/reports", json={"format": "pdf"}, headers=a).json()
    rep2 = c.post(f"/api/v1/cases/{cid}/reports", json={"format": "pdf"}, headers=a).json()
    assert rep1["state_hash"] != rep2["state_hash"]  # the first report generation is itself a ledger entry (state changed)
    export = c.get(f"/api/v1/cases/{cid}/custody/export", headers=a).content
    p = Path(app.state.ctx.settings.data_dir) / "custody.json"
    p.write_bytes(export)
    out = subprocess.run([str(BIN / f"veritas-verify{EXE}"), "export", str(p)], capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.strip().endswith("PASS"), out.stdout
