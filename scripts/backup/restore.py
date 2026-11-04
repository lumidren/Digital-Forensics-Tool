#!/usr/bin/env python3
"""Veritas restore: decrypt a backup archive into a fresh data directory and re-verify everything.

Verification performed after the files are in place (any failure makes the exit status non-zero):

1. archive integrity: AEAD authentication of every frame, the ``.sha256`` sidecar when present, and the
   SHA-256 of every extracted file against ``MANIFEST.json``;
2. custody: every ledger's hash chain and Ed25519 signatures with the Python verifier
   (``veritas.custody.ledger.verify_entries``), every anchor's head hash against the chain, and the
   independent Rust ``veritas-verify ledger`` when the binary is available (``--require-rust`` makes
   its absence a failure);
3. audit log: the hash chain of the restored ``audit.db`` (``veritas.audit.log.verify``);
4. SQLite databases: ``PRAGMA integrity_check``;
5. evidence store: every object in ``store-manifest.json`` exists in the WORM store, its stored bytes
   hash to the recorded value, and its metadata hashes match. ``--deep`` additionally decrypts and
   re-hashes the plaintext (MD5, SHA-256, SHA3-256) with the case keys derived from VERITAS_MASTER_KEY.

Usage
-----
    python scripts/backup/restore.py ARCHIVE.vbk --identity recovery.key --target /srv/veritas-restored \
        [--store-dir /mnt/worm/store | --s3-bucket veritas-evidence-prod] [--copy-store] [--deep] \
        [--database-url postgresql+psycopg://...] [--verifier target/release/veritas-verify] [--require-rust]

Prints a human-readable report, writes ``<target>/restore-report.json`` and exits 0 only on PASS.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from backup import BackupError, decrypt_stream, libpq_url, load_private_key, sha256_file  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
LAYOUT = {"db/veritas.db": "veritas.db", "timeline/timeline.db": "timeline.db", "audit/audit.db": "audit.db", "jobs/jobs.db": "jobs.db"}


@dataclass(slots=True)
class Report:
    checks: list[dict[str, Any]] = field(default_factory=list)
    timings_s: dict[str, float] = field(default_factory=dict)

    def add(self, name: str, ok: bool | None, detail: str = "") -> None:
        self.checks.append({"check": name, "result": "PASS" if ok else ("SKIP" if ok is None else "FAIL"), "detail": detail})

    @property
    def ok(self) -> bool:
        return all(c["result"] != "FAIL" for c in self.checks)

    @property
    def failures(self) -> list[dict[str, Any]]:
        return [c for c in self.checks if c["result"] == "FAIL"]

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": "PASS" if self.ok else "FAIL", "checks": self.checks, "timings_s": {k: round(v, 3) for k, v in self.timings_s.items()}}


# --------------------------------------------------------------------------- extraction
def _safe_members(tf: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = []
    for m in tf.getmembers():
        p = PurePosixPath(m.name)
        if p.is_absolute() or ".." in p.parts or not (m.isfile() or m.isdir()):
            raise BackupError(f"unsafe archive member rejected: {m.name}")
        members.append(m)
    return members


def extract(tar_bytes: io.BytesIO, dest: Path) -> Path:
    with tarfile.open(fileobj=tar_bytes, mode="r:gz") as tf:
        members = _safe_members(tf)
        roots = {PurePosixPath(m.name).parts[0] for m in members}
        if len(roots) != 1:
            raise BackupError("archive must contain exactly one top-level directory")
        tf.extractall(dest, members=members, filter="data")
    return dest / roots.pop()


def check_manifest(stage: Path, report: Report) -> dict[str, Any]:
    mpath = stage / "MANIFEST.json"
    if not mpath.exists():
        report.add("manifest.present", False, "MANIFEST.json missing")
        raise BackupError("MANIFEST.json missing")
    recorded = (stage / "MANIFEST.sha256").read_text(encoding="utf-8").split()[0] if (stage / "MANIFEST.sha256").exists() else None
    report.add("manifest.self_hash", recorded == sha256_file(mpath), "MANIFEST.json vs MANIFEST.sha256")
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    bad, missing = [], []
    for rel, info in sorted(manifest["files"].items()):
        p = stage / rel
        if not p.exists():
            missing.append(rel)
        elif sha256_file(p) != info["sha256"] or p.stat().st_size != info["size"]:
            bad.append(rel)
    present = {p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file()} - {"MANIFEST.json", "MANIFEST.sha256"}
    extra = sorted(present - set(manifest["files"]))
    report.add("manifest.file_hashes", not (bad or missing or extra), f"{len(manifest['files'])} files; mismatched={bad} missing={missing} unlisted={extra}")
    return manifest


def place(stage: Path, target: Path, manifest: dict[str, Any]) -> None:
    for rel in manifest["files"]:
        src = stage / rel
        if rel in LAYOUT:
            dst = target / LAYOUT[rel]
        elif rel.split("/", 1)[0] in ("ledgers", "keys", "reports"):
            dst = target / rel
        else:
            dst = target / "restore-meta" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        if dst.parent.name == "keys":
            os.chmod(dst, 0o600)
    meta = target / "restore-meta"
    meta.mkdir(exist_ok=True)
    shutil.copyfile(stage / "MANIFEST.json", meta / "MANIFEST.json")


# --------------------------------------------------------------------------- verification
def find_verifier(explicit: str | None) -> Path | None:
    exe = "veritas-verify" + (".exe" if os.name == "nt" else "")
    candidates = [explicit] if explicit else []
    if os.environ.get("VERITAS_BIN_DIR"):
        candidates.append(str(Path(os.environ["VERITAS_BIN_DIR"]) / exe))
    candidates += [str(REPO / "target" / "release" / exe), shutil.which("veritas-verify") or ""]
    for c in candidates:
        if c and Path(c).is_file():
            return Path(c)
    return None


def verify_ledgers(target: Path, report: Report, verifier: Path | None, require_rust: bool) -> None:
    from veritas.custody.ledger import verify_entries

    registry_path = target / "keys" / "registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8")) if registry_path.exists() else {"keys": []}
    ledgers = sorted(p for p in (target / "ledgers").glob("*.jsonl") if not p.name.endswith(".anchors.jsonl")) if (target / "ledgers").is_dir() else []
    if not ledgers:
        report.add("custody.ledgers", None, "no ledgers in backup")
    if verifier is None:
        report.add("custody.rust_verifier", False if require_rust else None, "veritas-verify not found" + (" (required)" if require_rust else "; build with cargo build --release -p veritas-ledger"))
    for led in ledgers:
        case_id = led.stem
        try:
            entries = [json.loads(line) for line in led.read_text(encoding="utf-8").splitlines() if line.strip()]
        except ValueError as exc:
            report.add(f"custody.python[{case_id}]", False, f"unparseable ledger line: {exc}")
            continue
        ok, failures = verify_entries(entries, registry)
        report.add(f"custody.python[{case_id}]", ok, f"{len(entries)} entries" + ("" if ok else f"; {failures[:5]}"))
        anchors_path = led.with_name(f"{case_id}.anchors.jsonl")
        if anchors_path.exists():
            by_seq = {e["seq"]: e["entry_hash"] for e in entries}
            anchors = [json.loads(line) for line in anchors_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            bad = [a["seq"] for a in anchors if by_seq.get(a["seq"]) != a["head_hash"]]
            report.add(f"custody.anchors[{case_id}]", not bad, f"{len(anchors)} anchors" + (f"; mismatched seq {bad}" if bad else ""))
        if verifier is not None:
            cmd = [str(verifier), "ledger", str(led), "--registry", str(registry_path)]
            if anchors_path.exists():
                cmd += ["--anchors", str(anchors_path)]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            verdict = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else proc.stderr.strip()[-200:]
            report.add(f"custody.rust[{case_id}]", proc.returncode == 0 and verdict == "PASS", verdict)


def verify_audit(target: Path, report: Report) -> None:
    from veritas.audit.log import verify

    db = target / "audit.db"
    if not db.exists():
        report.add("audit.chain", None, "no audit log in backup")
        return
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        rows = [{"seq": r[0], "ts": r[1], "actor": r[2], "action": r[3], "case_id": r[4], "target": r[5], "detail": json.loads(r[6]), "prev_hash": r[7], "row_hash": r[8]}
                for r in con.execute("SELECT seq, ts, actor, action, case_id, target, detail, prev_hash, row_hash FROM audit ORDER BY seq")]
    finally:
        con.close()
    ok, failures = verify(rows)
    report.add("audit.chain", ok, f"{len(rows)} rows" + ("" if ok else f"; {failures[:5]}"))


def verify_sqlite(target: Path, report: Report) -> None:
    for name in LAYOUT.values():
        p = target / name
        if not p.exists():
            continue
        con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
        try:
            res = con.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            con.close()
        report.add(f"sqlite.integrity[{name}]", res == "ok", res)


def verify_local_store(store_manifest: dict[str, Any], store_dir: Path, report: Report, deep: bool, copy_to: Path | None) -> None:
    from veritas.store.content import CaseKeyring, LocalStore

    if not store_dir.is_dir():
        report.add("store.location", False, f"store directory {store_dir} not found")
        return
    keyring = CaseKeyring.from_env()
    bad: list[str] = []
    for o in store_manifest["objects"]:
        a = o["address"]
        obj = store_dir / "objects" / a[:2] / a[2:4] / a
        mp = store_dir / "meta" / f"{a}.json"
        if not obj.exists() or not mp.exists():
            bad.append(f"{a[:16]} missing")
            continue
        meta = json.loads(mp.read_text(encoding="utf-8"))
        if meta["hashes"] != o["hashes"] or meta["case_id"] != o["case_id"]:
            bad.append(f"{a[:16]} metadata differs")
            continue
        if sha256_file(obj) != o["stored_sha256"]:
            bad.append(f"{a[:16]} stored bytes differ")
            continue
        if copy_to is not None:
            for src, dst in ((obj, copy_to / "objects" / a[:2] / a[2:4] / a), (mp, copy_to / "meta" / f"{a}.json")):
                dst.parent.mkdir(parents=True, exist_ok=True)
                if not dst.exists():
                    shutil.copyfile(src, dst)
                    os.chmod(dst, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    report.add("store.objects", not bad, f"{len(store_manifest['objects'])} objects at {store_dir}" + (f"; {bad[:10]}" if bad else ""))
    if deep:
        if keyring is None and any(o["encrypted"] for o in store_manifest["objects"]):
            report.add("store.deep", False, "VERITAS_MASTER_KEY required to re-hash encrypted objects")
            return
        st = LocalStore(store_dir, keyring)
        failed = [o["address"][:16] for o in store_manifest["objects"] if not st.verify(o["address"])]
        report.add("store.deep", not failed, "plaintext MD5/SHA-256/SHA3-256 re-hashed" + (f"; failed {failed[:10]}" if failed else ""))


def verify_s3_store(store_manifest: dict[str, Any], bucket: str, report: Report, deep: bool) -> None:
    import boto3

    s3 = boto3.client("s3", endpoint_url=os.environ.get("S3_ENDPOINT_URL"))
    lock = s3.get_object_lock_configuration(Bucket=bucket).get("ObjectLockConfiguration", {})
    report.add("store.object_lock", lock.get("ObjectLockEnabled") == "Enabled" and lock.get("Rule", {}).get("DefaultRetention", {}).get("Mode") == "COMPLIANCE", json.dumps(lock))
    bad: list[str] = []
    for o in store_manifest["objects"]:
        a = o["address"]
        try:
            head = s3.head_object(Bucket=bucket, Key=f"objects/{a[:2]}/{a[2:4]}/{a}", ChecksumMode="ENABLED")
        except Exception as exc:
            bad.append(f"{a[:16]} {type(exc).__name__}")
            continue
        if head.get("ChecksumSHA256") != o.get("stored_checksum_sha256_b64") or head["ContentLength"] != o["stored_size"]:
            bad.append(f"{a[:16]} checksum differs")
    report.add("store.objects", not bad, f"{len(store_manifest['objects'])} objects in s3://{bucket}" + (f"; {bad[:10]}" if bad else ""))
    if deep:
        from veritas.store.content import CaseKeyring, S3Store

        st = S3Store(bucket, CaseKeyring.from_env())
        failed = [o["address"][:16] for o in store_manifest["objects"] if not st.verify(o["address"])]
        report.add("store.deep", not failed, "plaintext re-hashed" + (f"; failed {failed[:10]}" if failed else ""))


def restore_postgres(dump: Path, database_url: str, report: Report) -> None:
    uri, env = libpq_url(database_url)
    proc = subprocess.run(["pg_restore", "--clean", "--if-exists", "--no-owner", "--no-privileges", "--exit-on-error", f"--dbname={uri}", str(dump)],
                          env={**os.environ, **env}, capture_output=True, text=True, check=False)
    report.add("db.pg_restore", proc.returncode == 0, proc.stderr.strip()[-300:])


# --------------------------------------------------------------------------- orchestration
def restore(archive: Path, identity_spec: str, target: Path, store_dir: Path | None = None, s3_bucket: str | None = None, copy_store: bool = False,
            deep: bool = False, database_url: str | None = None, verifier: str | None = None, require_rust: bool = False, work_dir: Path | None = None) -> Report:
    report = Report()
    t_all = time.perf_counter()
    if target.exists() and any(target.iterdir()):
        raise BackupError(f"target {target} is not empty; restore always goes into a fresh directory")
    target.mkdir(parents=True, exist_ok=True)
    # Extraction scratch space: private (0700) temp directory, short path for Windows path-length limits.
    work = Path(tempfile.mkdtemp(prefix="vr-", dir=work_dir))
    try:
        t = time.perf_counter()
        sidecar = archive.with_suffix(".vbk.sha256")
        if sidecar.exists():
            report.add("archive.sidecar_sha256", sidecar.read_text(encoding="utf-8").split()[0] == sha256_file(archive), sidecar.name)
        tar_bytes = io.BytesIO()
        try:
            with open(archive, "rb") as fh:
                decrypt_stream(fh, tar_bytes, load_private_key(identity_spec))
        except BackupError as exc:
            report.add("archive.decrypt", False, str(exc))
            return report
        report.add("archive.decrypt", True, "all frames authenticated")
        tar_bytes.seek(0)
        stage = extract(tar_bytes, work)
        report.timings_s["decrypt_extract"] = time.perf_counter() - t

        t = time.perf_counter()
        manifest = check_manifest(stage, report)
        place(stage, target, manifest)
        case_db = manifest["databases"].get("case", {})
        if case_db.get("engine") == "postgresql":
            if not database_url:
                report.add("db.pg_restore", False, "--database-url is required to restore a PostgreSQL dump")
            else:
                restore_postgres(stage / case_db["file"], database_url, report)
        tl = manifest["databases"].get("timeline", {})
        if tl.get("engine") == "clickhouse":
            report.add("timeline.clickhouse", None, f"server-side backup {tl['backup_id']}; run on the target cluster: {tl['restore_sql']}")
        report.timings_s["manifest_place"] = time.perf_counter() - t

        t = time.perf_counter()
        verify_ledgers(target, report, find_verifier(verifier), require_rust)
        report.timings_s["custody_verify"] = time.perf_counter() - t
        t = time.perf_counter()
        verify_audit(target, report)
        verify_sqlite(target, report)
        report.timings_s["audit_db_verify"] = time.perf_counter() - t

        t = time.perf_counter()
        store_manifest = json.loads((stage / "store-manifest.json").read_text(encoding="utf-8"))
        if store_manifest["backend"] == "s3" or s3_bucket:
            verify_s3_store(store_manifest, s3_bucket or store_manifest["location"].removeprefix("s3://"), report, deep)
        else:
            verify_local_store(store_manifest, store_dir or Path(store_manifest["location"]), report, deep, (target / "store") if copy_store else None)
        report.timings_s["store_verify"] = time.perf_counter() - t
    except BackupError as exc:
        report.add("restore", False, str(exc))
    finally:
        shutil.rmtree(work, ignore_errors=True)
        report.timings_s["total"] = time.perf_counter() - t_all
        (target / "restore-report.json").write_text(json.dumps(report.to_dict(), indent=1), encoding="utf-8")
    return report


def print_report(report: Report) -> None:
    for c in report.checks:
        print(f"{c['result']:<4}  {c['check']:<40} {c['detail']}")
    print("timings (s): " + ", ".join(f"{k}={v:.3f}" for k, v in report.timings_s.items()))
    print("PASS" if report.ok else "FAIL")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="veritas-restore", description=__doc__.split("\n\n")[0])
    ap.add_argument("archive")
    ap.add_argument("--identity", default=os.environ.get("VERITAS_BACKUP_IDENTITY"), help="recovery private key file or hex")
    ap.add_argument("--target", required=True, help="fresh (empty or absent) data directory")
    ap.add_argument("--store-dir", help="local WORM store to verify against (default: location recorded in the backup)")
    ap.add_argument("--s3-bucket", help="evidence bucket to verify against (cluster profile, e.g. the replica in the DR region)")
    ap.add_argument("--copy-store", action="store_true", help="native profile: copy verified objects from --store-dir into <target>/store")
    ap.add_argument("--deep", action="store_true", help="decrypt and re-hash every evidence object")
    ap.add_argument("--database-url", help="PostgreSQL target for pg_restore")
    ap.add_argument("--verifier", help="path to the Rust veritas-verify binary")
    ap.add_argument("--require-rust", action="store_true")
    ap.add_argument("--work-dir", help="scratch directory for decryption and extraction (default: system temp, mode 0700)")
    args = ap.parse_args(argv)
    if not args.identity:
        print("--identity (or VERITAS_BACKUP_IDENTITY) is required", file=sys.stderr)
        return 2
    try:
        report = restore(Path(args.archive).resolve(), args.identity, Path(args.target).resolve(), Path(args.store_dir).resolve() if args.store_dir else None,
                         args.s3_bucket, args.copy_store, args.deep, args.database_url, args.verifier, args.require_rust,
                         Path(args.work_dir).resolve() if args.work_dir else None)
    except (BackupError, OSError) as exc:
        print(f"FAIL  restore  {exc}")
        return 1
    print_report(report)
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
