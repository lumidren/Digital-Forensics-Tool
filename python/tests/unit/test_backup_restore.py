"""Backup and restore round trip for the native profile (scripts/backup).

Builds a small instance through ``AppContext``, backs it up to an archive sealed to a recovery key,
restores it into a fresh directory and expects every verification to PASS. Then tampers with one
custody ledger line inside the backup (both naively, and with the manifest re-hashed the way an
attacker holding the recovery public key could) and expects restore verification to FAIL.
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from veritas.api.config import load
from veritas.api.context import AppContext
from veritas.api.db import Case, User

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts" / "backup"))

import backup as vb  # noqa: E402
import restore as vr  # noqa: E402

MASTER = "5a" * 32


@pytest.fixture
def instance(tmp_path, monkeypatch):
    data = tmp_path / "var"
    monkeypatch.setenv("VERITAS_DATA_DIR", str(data))
    monkeypatch.setenv("VERITAS_MASTER_KEY", MASTER)
    for var in ("VERITAS_DATABASE_URL", "VERITAS_TIMELINE_URL", "VERITAS_STORE"):
        monkeypatch.delenv(var, raising=False)
    ctx = AppContext(load())
    case_id = "C-20260101-ABC123"
    with ctx.Session() as s:
        s.add(User(id="alice", display_name="Alice Examiner"))
        s.flush()
        ledger_id = ctx.create_ledger(case_id, "alice")
        s.add(Case(id=case_id, name="DR drill", created_by="alice", ledger_id=ledger_id))
        s.commit()
    for i in range(3):
        payload = (f"evidence object {i} ".encode() * 40000) + bytes([i])
        meta = ctx.store.put(case_id, io.BytesIO(payload), f"sample-{i}.bin")
        hashes = {"md5": meta.hashes.md5, "sha256": meta.hashes.sha256, "sha3_256": meta.hashes.sha3_256, "length": meta.hashes.length}
        ctx.custody(case_id, "alice", "ingest", f"evidence sample-{i}.bin stored", evidence_id=f"EV-{i:04d}", hashes=hashes, details={"store_address": meta.address})
        ctx.custody(case_id, "veritas-pipeline", "access", "parse", evidence_id=f"EV-{i:04d}", hashes=hashes)
        ctx.audit.append("alice", "POST /api/v1/cases/{case_id}/evidence", case_id, f"/api/v1/cases/{case_id}/evidence", {"status": 201})
    ctx.anchor(case_id)
    ctx.custody(case_id, "alice", "note", "post-anchor note")
    assert ctx.verify_custody(case_id)[0]
    ctx.engine.dispose()
    return data, case_id


@pytest.fixture
def recovery(tmp_path):
    pub, key = vb.keygen(tmp_path / "keys" / "recovery")
    return pub, key


def _backup(data: Path, out: Path, pub: Path) -> vb.BackupResult:
    return vb.create_backup(vb.Sources.from_env(str(data)), out, vb.load_public_key(str(pub)), now=datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc))


def _rewrite(archive: Path, key: Path, pub: Path, mutate, fix_manifest: bool) -> None:
    """Decrypt ``archive``, apply ``mutate(name -> bytes) -> dict`` and re-seal it to ``pub``."""
    tar_bytes = vb.read_archive(archive, vb.load_private_key(str(key)))
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=tar_bytes, mode="r:gz") as tf:
        for m in tf.getmembers():
            if m.isfile():
                files[m.name] = tf.extractfile(m).read()
    files = mutate(files)
    if fix_manifest:
        root = next(iter(files)).split("/", 1)[0]
        manifest = json.loads(files[f"{root}/MANIFEST.json"])
        for name, blob in files.items():
            rel = name.split("/", 1)[1]
            if rel in manifest["files"]:
                manifest["files"][rel] = {"sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)}
        files[f"{root}/MANIFEST.json"] = json.dumps(manifest, indent=1, sort_keys=True).encode()
        files[f"{root}/MANIFEST.sha256"] = (hashlib.sha256(files[f"{root}/MANIFEST.json"]).hexdigest() + "  MANIFEST.json\n").encode()
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tf:
        for name, blob in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(blob)
            tf.addfile(ti, io.BytesIO(blob))
    out.seek(0)
    with open(archive, "wb") as fh:
        vb.encrypt_stream(out, fh, vb.load_public_key(str(pub)))
    archive.with_suffix(".vbk.sha256").unlink(missing_ok=True)


def _tamper_ledger(case_id: str):
    def mutate(files: dict[str, bytes]) -> dict[str, bytes]:
        name = next(n for n in files if n.endswith(f"ledgers/{case_id}.jsonl"))
        lines = files[name].decode().splitlines()
        entry = json.loads(lines[2])
        entry["purpose"] = entry["purpose"] + " (edited)"
        lines[2] = json.dumps(entry, separators=(",", ":"))
        files[name] = ("\n".join(lines) + "\n").encode()
        return files
    return mutate


def test_backup_restore_roundtrip_passes(instance, recovery, tmp_path, monkeypatch):
    data, case_id = instance
    pub, key = recovery
    result = _backup(data, tmp_path / "backups", pub)
    assert result.archive.exists() and result.archive.suffix == ".vbk"
    assert result.manifest["counts"]["ledgers"] == 1 and result.manifest["counts"]["store_objects"] == 3
    assert not any(f.endswith("master.key") for f in result.manifest["files"])
    raw = result.archive.read_bytes()
    assert b"ledger created" not in raw and b"SQLite format 3" not in raw  # encrypted at rest

    target = tmp_path / "restored"
    report = vr.restore(result.archive, str(key), target, store_dir=data / "store", copy_store=True, deep=True)
    vr.print_report(report)
    assert report.ok, report.failures
    names = {c["check"] for c in report.checks if c["result"] == "PASS"}
    assert {f"custody.python[{case_id}]", f"custody.anchors[{case_id}]", "audit.chain", "store.objects", "store.deep", "manifest.file_hashes", "archive.decrypt"} <= names
    assert json.loads((target / "restore-report.json").read_text())["verdict"] == "PASS"

    # the restored directory is a working native instance
    monkeypatch.setenv("VERITAS_DATA_DIR", str(target))
    ctx = AppContext(load())
    assert ctx.verify_custody(case_id) == (True, [])
    assert all(ok for _, ok in ctx.store.iter_verify())
    with ctx.Session() as s:
        assert s.get(Case, case_id).name == "DR drill"
    ctx.engine.dispose()

    # the CLI reports PASS with exit status 0 on a second fresh target
    assert vr.main([str(result.archive), "--identity", str(key), "--target", str(tmp_path / "restored-cli"), "--store-dir", str(data / "store")]) == 0


def test_restore_fails_on_tampered_ledger_line(instance, recovery, tmp_path):
    data, case_id = instance
    pub, key = recovery
    result = _backup(data, tmp_path / "backups", pub)

    # 1) naive tamper: manifest hash catches it
    _rewrite(result.archive, key, pub, _tamper_ledger(case_id), fix_manifest=False)
    report = vr.restore(result.archive, str(key), tmp_path / "t1", store_dir=data / "store")
    assert not report.ok
    assert any(c["check"] == "manifest.file_hashes" and c["result"] == "FAIL" for c in report.checks)
    assert any(c["check"] == f"custody.python[{case_id}]" and c["result"] == "FAIL" for c in report.checks)

    # 2) tamper with the manifest re-hashed: the signed hash chain still catches it
    result = _backup(data, tmp_path / "backups2", pub)
    _rewrite(result.archive, key, pub, _tamper_ledger(case_id), fix_manifest=True)
    report = vr.restore(result.archive, str(key), tmp_path / "t2", store_dir=data / "store")
    assert not report.ok
    assert all(c["result"] != "FAIL" for c in report.checks if c["check"].startswith("manifest."))
    failed = [c for c in report.checks if c["result"] == "FAIL"]
    assert any(c["check"] == f"custody.python[{case_id}]" and "entry_hash mismatch" in c["detail"] for c in failed)
    assert vr.main([str(result.archive), "--identity", str(key), "--target", str(tmp_path / "t3"), "--store-dir", str(data / "store")]) == 1


def test_archive_frame_tampering_and_wrong_key_detected(instance, recovery, tmp_path):
    data, _ = instance
    pub, key = recovery
    result = _backup(data, tmp_path / "backups", pub)
    blob = bytearray(result.archive.read_bytes())
    blob[len(blob) // 2] ^= 0x01
    result.archive.write_bytes(bytes(blob))
    report = vr.restore(result.archive, str(key), tmp_path / "t1")
    assert not report.ok and any(c["check"] in ("archive.decrypt", "archive.sidecar_sha256") and c["result"] == "FAIL" for c in report.checks)

    other_pub, other_key = vb.keygen(tmp_path / "other" / "k")
    good = _backup(data, tmp_path / "backups2", pub)
    report = vr.restore(good.archive, str(other_key), tmp_path / "t2")
    assert any(c["check"] == "archive.decrypt" and c["result"] == "FAIL" for c in report.checks)

    truncated = good.archive.read_bytes()[:-100]
    good.archive.write_bytes(truncated)
    good.archive.with_suffix(".vbk.sha256").unlink()
    report = vr.restore(good.archive, str(key), tmp_path / "t3")
    assert any(c["check"] == "archive.decrypt" and c["result"] == "FAIL" for c in report.checks)


def test_restore_detects_missing_or_altered_evidence(instance, recovery, tmp_path):
    data, _ = instance
    pub, key = recovery
    result = _backup(data, tmp_path / "backups", pub)
    store_copy = tmp_path / "worm-replica"
    import shutil

    shutil.copytree(data / "store", store_copy)
    victim = sorted((store_copy / "objects").rglob("*"))[-1]
    victim.chmod(0o600)
    victim.write_bytes(b"replaced")
    report = vr.restore(result.archive, str(key), tmp_path / "t1", store_dir=store_copy)
    assert not report.ok
    assert any(c["check"] == "store.objects" and c["result"] == "FAIL" for c in report.checks)
    with pytest.raises(vb.BackupError):
        vr.restore(result.archive, str(key), tmp_path / "t1")  # target is not empty


def test_libpq_url_strips_password_and_driver():
    uri, env = vb.libpq_url("postgresql+psycopg://veritas:s%40cret@db.internal:5432/veritas?sslmode=require")
    assert uri == "postgresql://veritas@db.internal:5432/veritas?sslmode=require"
    assert env == {"PGPASSWORD": "s@cret"}
