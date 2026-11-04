"""Secrets never reach logs, the audit trail or the custody ledger. THREAT:T6.4

Runs an API session (login, case, upload, search, report, custody export, failed login with a
wrong password) with DEBUG JSON logging captured from every logger, then scans the captured log
text, the audit database export and every ledger line for: the passwords used, issued bearer
tokens, the master key, every examiner signing seed held by the key vault, and generic JWT /
private-key patterns.
"""
import io
import json
import logging
import re
from pathlib import Path

from fastapi.testclient import TestClient

from veritas.api.auth import hash_password
from veritas.api.config import load
from veritas.api.db import User
from veritas.api.main import create_app
from veritas.api.observability import JsonFormatter, scrub_text

PW = "Tr0ub4dor&3-horse-staple"
WRONG = "this-is-the-wrong-password-123"
MASTER = "5a" * 32


def test_scrub_text_patterns():
    s = scrub_text('password="hunter2" Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345 token=eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLXZhbHVl')
    assert "hunter2" not in s and "abcdefghijklmnopqrstuvwxyz012345" not in s and "eyJzdWIiOiJhbGljZSJ9" not in s


def test_no_secrets_anywhere(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "var"))
    monkeypatch.setenv("VERITAS_MASTER_KEY", MASTER)
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.addHandler(handler)
    old_level = root.level
    root.setLevel(logging.DEBUG)
    tokens: list[str] = []
    try:
        app = create_app(load(), start_processor=False)
        ctx = app.state.ctx
        with ctx.Session() as s:
            s.add(User(id="alice", display_name="Alice", password_hash=hash_password(PW), is_admin=True, can_unmask_pii=True))
            s.commit()
        with TestClient(app) as c:
            assert c.post("/api/v1/auth/login", json={"username": "alice", "password": WRONG}).status_code == 401
            t = c.post("/api/v1/auth/login", json={"username": "alice", "password": PW}).json()["access_token"]
            tokens.append(t)
            h = {"Authorization": f"Bearer {t}"}
            cid = c.post("/api/v1/cases", json={"name": "Secrets"}, headers=h).json()["id"]
            ev = c.post(f"/api/v1/cases/{cid}/evidence", files={"file": ("a.bin", io.BytesIO(b"abc" * 100))}, headers=h).json()
            c.post(f"/api/v1/cases/{cid}/timeline/search", json={"text": "x"}, headers=h)
            c.get(f"/api/v1/cases/{cid}/evidence/{ev['id']}/bytes", headers=h)
            c.post(f"/api/v1/cases/{cid}/reports", json={"format": "pdf"}, headers=h)
            c.get(f"/api/v1/cases/{cid}/custody/export", headers=h)
            c.get(f"/api/v1/cases/{cid}/timeline/search?access_token={t}")  # token in a query string must not be logged either
            logging.getLogger("veritas.test").info("login attempt with password=%s and Authorization: Bearer %s", PW, t)
        seeds = []
        for p in Path(ctx.settings.keys_dir).glob("*.key"):
            seeds.append(ctx.vault._box.decrypt(p.read_bytes()).hex())
        audit_text = json.dumps(ctx.audit.export())
        ledger_text = "\n".join(p.read_text(encoding="utf-8") for p in Path(ctx.settings.ledger_dir).glob("*.jsonl"))
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)
    logs = buf.getvalue()
    assert logs, "expected some log output"
    haystacks = {"logs": logs, "audit": audit_text, "ledger": ledger_text}
    secrets = {"password": PW, "wrong_password": WRONG, "master_key": MASTER, **{f"token{i}": t for i, t in enumerate(tokens)}, **{f"seed{i}": s for i, s in enumerate(seeds)}}
    assert seeds, "key vault should hold at least one signing seed"
    for where, text in haystacks.items():
        for name, secret in secrets.items():
            assert secret not in text, f"{name} leaked into {where}"
        assert not re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", text), f"private key leaked into {where}"
        assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}", text), f"JWT leaked into {where}"
