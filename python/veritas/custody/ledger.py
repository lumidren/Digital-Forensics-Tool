"""Python writer for the custody ledger, wire-compatible with ``crates/veritas-ledger``.

The API appends Access/Ingest/Export/Transform entries from Python. Entries produced here must
verify with the independent Rust ``veritas-verify`` binary, so this module reproduces exactly:

* the canonical JSON rules of ``canonical.rs`` (sorted keys by UTF-16 code units, no whitespace,
  integers only, minimal escapes with lower-case ``\\u00xx``);
* chrono's RFC 3339 serialization of ``DateTime<Utc>`` (``SecondsFormat::AutoSi`` with ``Z``):
  no fraction, 3, 6 or 9 fractional digits, whichever is the shortest exact form;
* the entry hash ``sha256(canonical(body) || signature_bytes)``.

The cross-language test ``tests/unit/test_custody_ledger.py`` writes a ledger here and runs the Rust
verifier on it.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey, VerifyKey

LEDGER_VERSION = 1
GENESIS_PREV_HASH = "0" * 64
KINDS = ("genesis", "acquire", "ingest", "access", "export", "transform", "key_enrolled", "key_revoked", "anchor", "note")


# --------------------------------------------------------------------------- canonical JSON
def _write_string(s: str, out: list[str]) -> None:
    out.append('"')
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')


def _utf16_key(s: str) -> list[int]:
    return list(s.encode("utf-16-be"))


def _write(v: Any, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        out.append(str(v))
    elif isinstance(v, float):
        raise ValueError("floating point numbers are not permitted in canonical JSON")
    elif isinstance(v, str):
        _write_string(v, out)
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _write(x, out)
        out.append("]")
    elif isinstance(v, dict):
        out.append("{")
        for i, k in enumerate(sorted(v, key=_utf16_key)):
            if i:
                out.append(",")
            _write_string(k, out)
            out.append(":")
            _write(v[k], out)
        out.append("}")
    else:
        raise TypeError(f"unsupported type in canonical JSON: {type(v).__name__}")


def canonical_bytes(v: Any) -> bytes:
    out: list[str] = []
    _write(v, out)
    return "".join(out).encode("utf-8")


# --------------------------------------------------------------------------- chrono timestamps
def rfc3339_autosi(dt: datetime) -> str:
    """Format like chrono ``to_rfc3339_opts(SecondsFormat::AutoSi, true)``."""
    dt = dt.astimezone(timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    us = dt.microsecond
    if us == 0:
        frac = ""
    elif us % 1000 == 0:
        frac = f".{us // 1000:03d}"
    else:
        frac = f".{us:06d}"
    return base + frac + "Z"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- keys
@dataclass(slots=True)
class ExaminerKey:
    signing: SigningKey

    @classmethod
    def generate(cls) -> "ExaminerKey":
        return cls(SigningKey.generate())

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> "ExaminerKey":
        return cls(SigningKey(bytes.fromhex(seed_hex)))

    @property
    def public_key_hex(self) -> str:
        return self.signing.verify_key.encode().hex()

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self.signing.verify_key.encode()).hexdigest()[:32]

    def sign(self, data: bytes) -> bytes:
        return self.signing.sign(data).signature

    def __repr__(self) -> str:  # never print secret material
        return f"ExaminerKey({self.key_id})"


def key_record(key: ExaminerKey, holder: str, role: str, valid_from: datetime, valid_to: datetime | None = None) -> dict[str, Any]:
    return {"key_id": key.key_id, "public_key": key.public_key_hex, "holder": holder, "role": role, "valid_from": rfc3339_autosi(valid_from), "valid_to": rfc3339_autosi(valid_to) if valid_to else None}


# --------------------------------------------------------------------------- entries
def tool_info(name: str, version: str, command_line: str, binary_sha256: str | None = None) -> dict[str, Any]:
    return {"name": name, "version": version, "binary_sha256": binary_sha256, "command_line": command_line}


def entry_hash(body_canonical: bytes, signature: bytes) -> str:
    return hashlib.sha256(body_canonical + signature).hexdigest()


def sign_entry(body: dict[str, Any], key: ExaminerKey) -> dict[str, Any]:
    cb = canonical_bytes(body)
    sig = key.sign(cb)
    return {**body, "signature": sig.hex(), "entry_hash": entry_hash(cb, sig)}


BODY_FIELDS = ("ledger_version", "ledger_id", "seq", "prev_hash", "timestamp", "actor", "actor_key_id", "kind", "evidence_id", "hashes", "device", "time_source", "tool", "purpose", "details")


def body_of(entry: dict[str, Any]) -> dict[str, Any]:
    return {k: entry[k] for k in BODY_FIELDS}


class Ledger:
    """Append-only JSON Lines ledger file with a process-wide lock."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def head(self) -> dict[str, Any] | None:
        entries = self.entries()
        return entries[-1] if entries else None

    def create(self, ledger_id: str, case_id: str, key: ExaminerKey, actor: str, tool: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self.path.exists() and self.path.stat().st_size > 0:
                raise FileExistsError(f"ledger {self.path} already exists")
            body = {
                "ledger_version": LEDGER_VERSION, "ledger_id": ledger_id, "seq": 0, "prev_hash": GENESIS_PREV_HASH,
                "timestamp": rfc3339_autosi(utcnow()), "actor": actor, "actor_key_id": key.key_id, "kind": "genesis",
                "evidence_id": None, "hashes": None, "device": None, "time_source": None, "tool": tool,
                "purpose": "ledger created", "details": {"case_id": case_id},
            }
            entry = sign_entry(body, key)
            self._append_line(entry)
            return entry

    def append(self, key: ExaminerKey, actor: str, kind: str, purpose: str, tool: dict[str, Any], evidence_id: str | None = None,
               hashes: dict[str, Any] | None = None, device: dict[str, Any] | None = None, time_source: dict[str, Any] | None = None,
               details: dict[str, Any] | None = None, timestamp: datetime | None = None) -> dict[str, Any]:
        if kind not in KINDS or kind == "genesis":
            raise ValueError(f"invalid entry kind {kind}")
        with self._lock:
            head = self.head()
            if head is None:
                raise FileNotFoundError("ledger has no genesis entry")
            ts = timestamp or utcnow()
            head_ts = datetime.fromisoformat(head["timestamp"].replace("Z", "+00:00"))
            if ts < head_ts:
                ts = head_ts  # monotonic: never write an entry that precedes its predecessor
            body = {
                "ledger_version": LEDGER_VERSION, "ledger_id": head["ledger_id"], "seq": head["seq"] + 1, "prev_hash": head["entry_hash"],
                "timestamp": rfc3339_autosi(ts), "actor": actor, "actor_key_id": key.key_id, "kind": kind, "evidence_id": evidence_id,
                "hashes": hashes, "device": device, "time_source": time_source, "tool": tool, "purpose": purpose, "details": details or {},
            }
            entry = sign_entry(body, key)
            self._append_line(entry)
            return entry

    def _append_line(self, entry: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())


def build_export(entries: list[dict[str, Any]], registry: dict[str, Any], anchors: list[dict[str, Any]], key: ExaminerKey, exported_by: str, exported_at: datetime | None = None) -> dict[str, Any]:
    export = {
        "format": "veritas-custody", "format_version": 1, "exported_at": rfc3339_autosi(exported_at or utcnow()), "exported_by": exported_by,
        "exporter_key_id": key.key_id, "head_hash": entries[-1]["entry_hash"] if entries else GENESIS_PREV_HASH, "entry_count": len(entries),
        "registry": registry, "anchors": anchors, "entries": entries, "signature": "",
    }
    export["signature"] = key.sign(canonical_bytes(export)).hex()
    return export


def verify_entries(entries: list[dict[str, Any]], registry: dict[str, Any]) -> tuple[bool, list[str]]:
    """In-process check used by the API; the Rust verifier remains the authoritative one."""
    failures: list[str] = []
    keys = {k["key_id"]: k for k in registry.get("keys", [])}
    prev = GENESIS_PREV_HASH
    for i, e in enumerate(entries):
        body = body_of(e)
        if e["seq"] != i:
            failures.append(f"seq {e['seq']}: expected {i}")
        if e["prev_hash"] != prev:
            failures.append(f"seq {e['seq']}: prev_hash mismatch")
        cb = canonical_bytes(body)
        sig = bytes.fromhex(e["signature"])
        if entry_hash(cb, sig) != e["entry_hash"]:
            failures.append(f"seq {e['seq']}: entry_hash mismatch")
        rec = keys.get(e["actor_key_id"])
        if rec is None:
            failures.append(f"seq {e['seq']}: unknown key")
        else:
            try:
                VerifyKey(bytes.fromhex(rec["public_key"])).verify(cb, sig)
            except Exception:
                failures.append(f"seq {e['seq']}: bad signature")
        prev = e["entry_hash"]
    return (not failures, failures)
