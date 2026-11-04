"""Cross-language test: the Python ledger writer must satisfy the Rust verifier."""
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from veritas.custody.ledger import (
    ExaminerKey, Ledger, build_export, canonical_bytes, key_record, rfc3339_autosi, tool_info, verify_entries,
)

ROOT = Path(__file__).resolve().parents[3]


def verifier() -> Path | None:
    for d in ("release", "debug"):
        p = ROOT / "target" / d / "veritas-verify.exe"
        if p.exists():
            return p
        p = ROOT / "target" / d / "veritas-verify"
        if p.exists():
            return p
    return None


def test_canonical_matches_rust_rules():
    assert canonical_bytes({"b": 1, "a": {"z": [1, 2, {"y": "x"}], "c": None}}) == b'{"a":{"c":null,"z":[1,2,{"y":"x"}]},"b":1}'
    assert canonical_bytes({"s": 'a"b\\c\n\x01'}) == b'{"s":"a\\"b\\\\c\\n\\u0001"}'
    with pytest.raises(ValueError):
        canonical_bytes({"x": 1.5})
    # UTF-16 code-unit ordering (as in Rust's encode_utf16 sort): U+1F600 encodes as surrogate D83D,
    # which sorts BEFORE U+FF61, the opposite of code-point order.
    out = canonical_bytes({"\U0001F600": 1, "｡": 2})
    assert out.index("\U0001F600".encode()) < out.index("｡".encode())


def test_rfc3339_autosi():
    base = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert rfc3339_autosi(base) == "2026-01-02T03:04:05Z"
    assert rfc3339_autosi(base.replace(microsecond=120000)) == "2026-01-02T03:04:05.120Z"
    assert rfc3339_autosi(base.replace(microsecond=123456)) == "2026-01-02T03:04:05.123456Z"


def _ledger(tmp_path):
    key = ExaminerKey.generate()
    led = Ledger(tmp_path / "ledger.jsonl")
    t = tool_info("veritas-api", "0.1.0", "pytest")
    led.create("L-PY", "CASE-PY", key, "alice", t)
    led.append(key, "alice", "ingest", "stored image", t, evidence_id="EV-1",
               hashes={"md5": "0" * 32, "sha256": "1" * 64, "sha3_256": "2" * 64, "length": 4096},
               device={"description": "laptop ssd", "serial": "S1", "model": None, "size_bytes": 4096, "sector_size": 512, "write_blocked": True, "host": "WS01"},
               time_source={"source": "ntp:pool.ntp.org", "offset_ms": -12, "uncertainty_ms": 40})
    led.append(key, "bob", "access", "parsed by evtx", t, evidence_id="EV-1", details={"parser": "evtx", "bytes": 4096, "unicode": "é✓"})
    registry = {"keys": [key_record(key, "alice", "admin", datetime.now(timezone.utc) - timedelta(minutes=5))]}
    return key, led, registry


def test_python_verify_and_tamper(tmp_path):
    key, led, registry = _ledger(tmp_path)
    entries = led.entries()
    ok, failures = verify_entries(entries, registry)
    assert ok, failures
    entries[1]["purpose"] = "changed"
    assert not verify_entries(entries, registry)[0]
    with pytest.raises(FileExistsError):
        led.create("x", "y", key, "a", {})
    with pytest.raises(ValueError):
        led.append(key, "a", "genesis", "p", {})
    assert "ExaminerKey(" in repr(key) and key.signing.encode().hex() not in repr(key)


@pytest.mark.skipif(verifier() is None, reason="veritas-verify not built")
def test_rust_verifier_accepts_python_ledger(tmp_path):
    key, led, registry = _ledger(tmp_path)
    reg_path = tmp_path / "registry.json"
    reg_path.write_text(json.dumps(registry), encoding="utf-8")
    out = subprocess.run([str(verifier()), "ledger", str(led.path), "--registry", str(reg_path)], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
    assert out.stdout.strip().endswith("PASS")

    export = build_export(led.entries(), registry, [], key, "alice")
    exp_path = tmp_path / "custody.json"
    exp_path.write_text(json.dumps(export, ensure_ascii=False, indent=2), encoding="utf-8")
    out = subprocess.run([str(verifier()), "export", str(exp_path)], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr

    export["entries"][2]["details"]["bytes"] = 1
    exp_path.write_text(json.dumps(export), encoding="utf-8")
    out = subprocess.run([str(verifier()), "export", str(exp_path)], capture_output=True, text=True)
    assert out.returncode == 1 and out.stdout.strip().endswith("FAIL")
