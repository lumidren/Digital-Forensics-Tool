"""Hash-chained audit log.

Every API request that reads or changes case data appends a row. Each row embeds the SHA-256 of
the previous row, so removal or alteration of any row is detectable by :func:`verify`. The log is
exported with the custody report and re-verified by the same routine. THREAT:T5.2
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64


@dataclass(slots=True)
class AuditRow:
    seq: int
    ts: str
    actor: str
    action: str
    case_id: str | None
    target: str | None
    detail: dict[str, Any]
    prev_hash: str
    row_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "ts": self.ts, "actor": self.actor, "action": self.action, "case_id": self.case_id,
            "target": self.target, "detail": self.detail, "prev_hash": self.prev_hash, "row_hash": self.row_hash,
        }


def _row_hash(seq: int, ts: str, actor: str, action: str, case_id: str | None, target: str | None, detail: dict[str, Any], prev_hash: str) -> str:
    payload = json.dumps([seq, ts, actor, action, case_id, target, detail, prev_hash], sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_SECRET_KEYS = {"password", "passphrase", "token", "secret", "api_key", "authorization", "cookie", "client_secret"}


def scrub(detail: dict[str, Any]) -> dict[str, Any]:
    """Remove secret-looking keys before anything is persisted or logged."""
    out: dict[str, Any] = {}
    for k, v in detail.items():
        if k.lower() in _SECRET_KEYS or any(s in k.lower() for s in ("passw", "secret", "token")):
            out[k] = "[redacted]"
        elif isinstance(v, dict):
            out[k] = scrub(v)
        else:
            out[k] = v
    return out


class AuditLog:
    def __init__(self, path: str | Path, clock=None):
        self.path = str(path)
        self._lock = threading.Lock()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS audit(
                seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
                case_id TEXT, target TEXT, detail TEXT NOT NULL, prev_hash TEXT NOT NULL, row_hash TEXT NOT NULL UNIQUE)"""
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_audit_case ON audit(case_id, seq)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_audit_actor ON audit(actor, seq)")

    def head(self) -> tuple[int, str]:
        row = self._conn.execute("SELECT seq, row_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return (int(row[0]), row[1]) if row else (-1, GENESIS)

    def append(self, actor: str, action: str, case_id: str | None = None, target: str | None = None, detail: dict[str, Any] | None = None) -> AuditRow:
        detail = scrub(detail or {})
        with self._lock:
            seq, prev = self.head()
            seq += 1
            ts = self._clock().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            h = _row_hash(seq, ts, actor, action, case_id, target, detail, prev)
            self._conn.execute(
                "INSERT INTO audit(seq, ts, actor, action, case_id, target, detail, prev_hash, row_hash) VALUES(?,?,?,?,?,?,?,?,?)",
                (seq, ts, actor, action, case_id, target, json.dumps(detail, sort_keys=True, ensure_ascii=False), prev, h),
            )
            return AuditRow(seq, ts, actor, action, case_id, target, detail, prev, h)

    def rows(self, case_id: str | None = None, actor: str | None = None, limit: int = 1000, offset: int = 0) -> Iterator[AuditRow]:
        sql = "SELECT seq, ts, actor, action, case_id, target, detail, prev_hash, row_hash FROM audit"
        clauses: list[str] = []
        params: list[Any] = []
        if case_id is not None:
            clauses.append("case_id = ?")
            params.append(case_id)
        if actor is not None:
            clauses.append("actor = ?")
            params.append(actor)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq LIMIT ? OFFSET ?"
        params += [limit, offset]
        for r in self._conn.execute(sql, params):
            yield AuditRow(int(r[0]), r[1], r[2], r[3], r[4], r[5], json.loads(r[6]), r[7], r[8])

    def all_rows(self) -> list[AuditRow]:
        return list(self.rows(limit=10**12))

    def export(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.all_rows()]


def verify(rows: list[dict[str, Any]] | list[AuditRow]) -> tuple[bool, list[str]]:
    """Re-validate the chain from scratch. Returns (ok, failures)."""
    failures: list[str] = []
    prev = GENESIS
    expected_seq = 0
    for r in rows:
        d = r.to_dict() if isinstance(r, AuditRow) else r
        if d["seq"] != expected_seq:
            failures.append(f"seq {d['seq']}: expected {expected_seq}")
        if d["prev_hash"] != prev:
            failures.append(f"seq {d['seq']}: prev_hash mismatch")
        h = _row_hash(d["seq"], d["ts"], d["actor"], d["action"], d["case_id"], d["target"], d["detail"], d["prev_hash"])
        if h != d["row_hash"]:
            failures.append(f"seq {d['seq']}: row_hash mismatch")
        prev = d["row_hash"]
        expected_seq = d["seq"] + 1
    return (not failures, failures)
