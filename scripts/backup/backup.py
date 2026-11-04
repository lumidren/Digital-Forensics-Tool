#!/usr/bin/env python3
"""Veritas backup: case database, timeline index, audit log, custody ledgers, anchors, key registry.

What goes into a backup archive
-------------------------------
``db/``        case database: SQLite online-backup copy (native) or ``pg_dump --format=custom`` (cluster)
``timeline/``  SQLite timeline copy (native); for ClickHouse a server-side ``BACKUP DATABASE`` is issued and
               only its descriptor is recorded (the ClickHouse backup lands on the configured backup disk / S3)
``audit/``     hash-chained audit log (SQLite online-backup copy)
``jobs/``      processing job state (SQLite online-backup copy)
``ledgers/``   every custody ledger ``<case>.jsonl`` and anchor file ``<case>.anchors.jsonl``
``keys/``      key registry (public keys, validity windows), sealed examiner key files, token signing key.
               ``master.key`` is excluded unless ``--include-master-key`` is given: the master key is
               escrowed separately (KMS / HSM / sealed envelope), see docs/DR.md.
``reports/``   generated reports and their detached signatures
``store-manifest.json``
               evidence store inventory: address, hashes, case, size and the SHA-256 of the stored
               (possibly encrypted) object. Evidence bytes are NOT copied: they live in the WORM store
               (S3 Object Lock COMPLIANCE + cross-region replication, or a read-only local volume).
``MANIFEST.json``
               SHA-256 and size of every file above, the source profile and timings.

The tar.gz archive is encrypted to a recovery X25519 public key: a random 32-byte file key is sealed
with a NaCl sealed box (X25519 + XSalsa20-Poly1305) and the archive is streamed through
XChaCha20-Poly1305 in 1 MiB frames whose associated data binds the frame index and a final-frame flag,
so truncation, reordering and frame substitution are detected. A ``.sha256`` sidecar records the
digest of the encrypted file for transport checks.

Usage
-----
    python scripts/backup/backup.py keygen --out /secure/recovery          # once, offline
    python scripts/backup/backup.py create --recipient /secure/recovery.pub --out /backups
    python scripts/backup/backup.py create --data-dir var --recipient-hex <hex> --out backups

Environment: VERITAS_DATA_DIR, VERITAS_DATABASE_URL, VERITAS_TIMELINE_URL, VERITAS_STORE,
VERITAS_S3_BUCKET, S3_ENDPOINT_URL, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD, VERITAS_BACKUP_RECIPIENT.
Exit status 0 on success, 1 on failure. Emits a one-line JSON summary on stdout (consumed by the
backup CronJob, which publishes ``veritas_backup_last_success_timestamp_seconds``).
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt, crypto_aead_xchacha20poly1305_ietf_encrypt
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.utils import random as nacl_random

FORMAT_VERSION = 1
MAGIC = b"VERITAS-BACKUP\x00\x01"
FRAME = 1 << 20
SQLITE_FILES = {"veritas.db": "db", "timeline.db": "timeline", "audit.db": "audit", "jobs.db": "jobs"}


class BackupError(Exception):
    pass


# --------------------------------------------------------------------------- hashing helpers
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(FRAME), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_stamp(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")


# --------------------------------------------------------------------------- recovery keys
def load_public_key(spec: str) -> PublicKey:
    """``spec`` is a hex string or a path to a file containing one."""
    text = spec.strip()
    p = Path(text)
    if len(text) != 64 and p.exists():
        text = p.read_text(encoding="utf-8").strip()
    raw = bytes.fromhex(text)
    if len(raw) != 32:
        raise BackupError("recovery public key must be 32 bytes (64 hex characters)")
    return PublicKey(raw)


def load_private_key(spec: str) -> PrivateKey:
    text = spec.strip()
    p = Path(text)
    if len(text) != 64 and p.exists():
        text = p.read_text(encoding="utf-8").strip()
    raw = bytes.fromhex(text)
    if len(raw) != 32:
        raise BackupError("recovery private key must be 32 bytes (64 hex characters)")
    return PrivateKey(raw)


def keygen(out_prefix: Path) -> tuple[Path, Path]:
    sk = PrivateKey.generate()
    pub, key = out_prefix.with_suffix(".pub"), out_prefix.with_suffix(".key")
    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(bytes(sk).hex() + "\n")
    pub.write_text(bytes(sk.public_key).hex() + "\n", encoding="utf-8")
    return pub, key


# --------------------------------------------------------------------------- stream encryption
def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + index.to_bytes(8, "little")


def _aad(index: int, final: bool) -> bytes:
    return MAGIC + index.to_bytes(8, "little") + (b"\x01" if final else b"\x00")


def encrypt_stream(src: BinaryIO, dst: BinaryIO, recipient: PublicKey) -> None:
    file_key = nacl_random(32)
    sealed = SealedBox(recipient).encrypt(file_key)
    prefix = nacl_random(16)
    dst.write(MAGIC)
    dst.write(len(sealed).to_bytes(2, "little"))
    dst.write(sealed)
    dst.write(prefix)
    index = 0
    chunk = src.read(FRAME)
    while True:
        nxt = src.read(FRAME)
        final = not nxt
        ct = crypto_aead_xchacha20poly1305_ietf_encrypt(chunk, _aad(index, final), _nonce(prefix, index), file_key)
        dst.write(len(ct).to_bytes(4, "little"))
        dst.write(ct)
        if final:
            break
        chunk, index = nxt, index + 1


def decrypt_stream(src: BinaryIO, dst: BinaryIO, identity: PrivateKey) -> None:
    if src.read(len(MAGIC)) != MAGIC:
        raise BackupError("not a Veritas backup archive (bad magic)")
    n = int.from_bytes(src.read(2), "little")
    try:
        file_key = SealedBox(identity).decrypt(src.read(n))
    except Exception as exc:
        raise BackupError("cannot unseal the archive key: wrong recovery key or corrupted header") from exc
    prefix = src.read(16)
    if len(prefix) != 16:
        raise BackupError("truncated archive header")
    index = 0
    while True:
        hdr = src.read(4)
        if len(hdr) != 4:
            raise BackupError("archive truncated before the final frame")
        size = int.from_bytes(hdr, "little")
        if size > FRAME + 16:
            raise BackupError("frame length exceeds maximum")
        ct = src.read(size)
        if len(ct) != size:
            raise BackupError("truncated frame")
        pt = None
        for final in (False, True):
            try:
                pt = crypto_aead_xchacha20poly1305_ietf_decrypt(ct, _aad(index, final), _nonce(prefix, index), file_key)
            except Exception:
                continue
            dst.write(pt)
            if final:
                if src.read(1):
                    raise BackupError("trailing data after the final frame")
                return
            break
        if pt is None:
            raise BackupError(f"frame {index} failed authentication (tampered or corrupted archive)")
        index += 1


# --------------------------------------------------------------------------- sources
@dataclass(slots=True)
class Sources:
    data_dir: Path
    database_url: str
    timeline_url: str
    store_backend: str
    s3_bucket: str | None
    master_key_hex: str | None

    @classmethod
    def from_env(cls, data_dir: str | None = None) -> "Sources":
        d = Path(data_dir or os.environ.get("VERITAS_DATA_DIR") or (Path.cwd() / "var")).resolve()
        return cls(
            data_dir=d,
            database_url=os.environ.get("VERITAS_DATABASE_URL", f"sqlite:///{(d / 'veritas.db').as_posix()}"),
            timeline_url=os.environ.get("VERITAS_TIMELINE_URL", f"sqlite:///{(d / 'timeline.db').as_posix()}"),
            store_backend=os.environ.get("VERITAS_STORE", "local"),
            s3_bucket=os.environ.get("VERITAS_S3_BUCKET"),
            master_key_hex=os.environ.get("VERITAS_MASTER_KEY"),
        )


def sqlite_path(url: str) -> Path | None:
    if url.startswith("sqlite:///"):
        return Path(url[len("sqlite:///"):])
    return None


def sqlite_online_backup(src: Path, dst: Path) -> None:
    """Consistent copy of a live SQLite database through the online backup API."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    s = sqlite3.connect(f"file:{src.as_posix()}?mode=ro", uri=True)
    d = sqlite3.connect(dst)
    try:
        with d:
            s.backup(d, pages=4096)
    finally:
        d.close()
        s.close()


def libpq_url(sqlalchemy_url: str) -> tuple[str, dict[str, str]]:
    """Turn ``postgresql+psycopg://u:p@h/db`` into a password-free libpq URI plus PGPASSWORD env."""
    parsed = urllib.parse.urlsplit(sqlalchemy_url)
    scheme = parsed.scheme.split("+", 1)[0]
    env: dict[str, str] = {}
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc += f":{parsed.port}"
    if parsed.username:
        netloc = f"{urllib.parse.quote(parsed.username)}@{netloc}"
    if parsed.password:
        env["PGPASSWORD"] = urllib.parse.unquote(parsed.password)
    return urllib.parse.urlunsplit((scheme, netloc, parsed.path, parsed.query, "")), env


def pg_dump(url: str, dst: Path) -> None:
    uri, env = libpq_url(url)
    dst.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(["pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--serializable-deferrable", f"--file={dst}", f"--dbname={uri}"],
                          env={**os.environ, **env}, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise BackupError(f"pg_dump failed: {proc.stderr.strip()[-500:]}")


def clickhouse_backup(url: str, name: str, target: str | None) -> dict[str, Any]:
    """Issue a server-side ``BACKUP DATABASE``; returns its descriptor for the manifest."""
    import httpx

    rest = url[len("clickhouse://"):]
    host, _, db = rest.partition("/")
    db = db or "veritas"
    target = target or f"Disk('backups', '{name}.zip')"
    auth = (os.environ["CLICKHOUSE_USER"], os.environ.get("CLICKHOUSE_PASSWORD", "")) if os.environ.get("CLICKHOUSE_USER") else None
    sql = f"BACKUP DATABASE {db} TO {target} SETTINGS id = '{name}'"
    r = httpx.post(f"http://{host}", params={"query": sql}, auth=auth, timeout=3600.0)
    if r.status_code != 200:
        raise BackupError(f"ClickHouse BACKUP failed: {r.text.strip()[-500:]}")
    status = r.text.strip().split("\t")
    return {"engine": "clickhouse", "database": db, "target": target, "backup_id": name, "status": status[-1] if status else "", "restore_sql": f"RESTORE DATABASE {db} FROM {target}"}


# --------------------------------------------------------------------------- evidence store manifest
def local_store_manifest(store_dir: Path) -> dict[str, Any]:
    objects: list[dict[str, Any]] = []
    meta_dir = store_dir / "meta"
    for mp in sorted(meta_dir.glob("*.json")) if meta_dir.is_dir() else []:
        meta = json.loads(mp.read_text(encoding="utf-8"))
        a = meta["address"]
        obj = store_dir / "objects" / a[:2] / a[2:4] / a
        objects.append({
            "address": a, "case_id": meta["case_id"], "encrypted": meta["encrypted"], "hashes": meta["hashes"],
            "stored_size": obj.stat().st_size if obj.exists() else None, "stored_sha256": sha256_file(obj) if obj.exists() else None,
            "meta_sha256": sha256_file(mp),
        })
    return {"backend": "local", "location": str(store_dir), "object_count": len(objects), "plaintext_bytes": sum(o["hashes"]["length"] for o in objects), "objects": objects}


def s3_store_manifest(bucket: str) -> dict[str, Any]:
    import boto3

    s3 = boto3.client("s3", endpoint_url=os.environ.get("S3_ENDPOINT_URL"))
    lock = s3.get_object_lock_configuration(Bucket=bucket).get("ObjectLockConfiguration", {})
    objects: list[dict[str, Any]] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="meta/"):
        for o in page.get("Contents", []):
            a = o["Key"][5:-5]
            meta = json.loads(s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read())
            head = s3.head_object(Bucket=bucket, Key=f"objects/{a[:2]}/{a[2:4]}/{a}", ChecksumMode="ENABLED")
            objects.append({
                "address": a, "case_id": meta["case_id"], "encrypted": meta["encrypted"], "hashes": meta["hashes"],
                "stored_size": head["ContentLength"], "stored_checksum_sha256_b64": head.get("ChecksumSHA256"), "version_id": head.get("VersionId"),
                "object_lock_mode": head.get("ObjectLockMode"), "retain_until": head["ObjectLockRetainUntilDate"].isoformat() if head.get("ObjectLockRetainUntilDate") else None,
            })
    return {"backend": "s3", "location": f"s3://{bucket}", "object_lock": lock, "object_count": len(objects), "plaintext_bytes": sum(o["hashes"]["length"] for o in objects), "objects": objects}


# --------------------------------------------------------------------------- archive
def iter_files(root: Path) -> Iterator[Path]:
    for p in sorted(root.rglob("*")):
        if p.is_file():
            yield p


def _copy_tree(src: Path, dst: Path, exclude: set[str]) -> int:
    n = 0
    if not src.is_dir():
        return 0
    for p in sorted(src.rglob("*")):
        if p.is_file() and p.name not in exclude:
            target = dst / p.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, target)
            n += 1
    return n


def _tar_filter(ti: tarfile.TarInfo) -> tarfile.TarInfo:
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.mode = 0o600 if ti.isfile() else 0o700
    return ti


@dataclass(slots=True)
class BackupResult:
    archive: Path
    archive_sha256: str
    manifest: dict[str, Any]
    timings_s: dict[str, float] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {"ok": True, "archive": str(self.archive), "archive_sha256": self.archive_sha256, "archive_size": self.archive.stat().st_size, "files": len(self.manifest["files"]),
                "ledgers": self.manifest["counts"]["ledgers"], "store_objects": self.manifest["counts"]["store_objects"], "timings_s": self.timings_s}


def create_backup(src: Sources, out_dir: Path, recipient: PublicKey, include_master_key: bool = False, clickhouse_target: str | None = None,
                  now: datetime | None = None, work_dir: Path | None = None) -> BackupResult:
    t_all = time.perf_counter()
    timings: dict[str, float] = {}
    stamp = utc_stamp(now)
    name = f"veritas-backup-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    # Plaintext staging lives next to the output (same volume, same access controls) unless --work-dir
    # says otherwise; names are kept short for Windows path-length limits.
    work = Path(tempfile.mkdtemp(prefix="vb-", dir=work_dir or out_dir))
    try:
        stage = work / "s"
        stage.mkdir()
        manifest: dict[str, Any] = {"format": "veritas-backup", "format_version": FORMAT_VERSION, "name": name, "created_at": (now or datetime.now(timezone.utc)).isoformat(),
                                    "source": {"data_dir": str(src.data_dir), "store_backend": src.store_backend}, "databases": {}, "files": {}, "counts": {}}
        # case database
        t = time.perf_counter()
        db_path = sqlite_path(src.database_url)
        if db_path is not None:
            if not db_path.exists():
                raise BackupError(f"case database {db_path} does not exist")
            sqlite_online_backup(db_path, stage / "db" / "veritas.db")
            manifest["databases"]["case"] = {"engine": "sqlite", "file": "db/veritas.db"}
        elif src.database_url.startswith("postgresql"):
            pg_dump(src.database_url, stage / "db" / "veritas.pgdump")
            manifest["databases"]["case"] = {"engine": "postgresql", "file": "db/veritas.pgdump", "format": "pg_dump custom"}
        else:
            raise BackupError(f"unsupported database url scheme: {src.database_url.split(':', 1)[0]}")
        timings["case_db"] = time.perf_counter() - t
        # timeline
        t = time.perf_counter()
        tl_path = sqlite_path(src.timeline_url)
        if tl_path is not None:
            if tl_path.exists():
                sqlite_online_backup(tl_path, stage / "timeline" / "timeline.db")
                manifest["databases"]["timeline"] = {"engine": "sqlite", "file": "timeline/timeline.db"}
            else:
                manifest["databases"]["timeline"] = {"engine": "sqlite", "file": None}
        elif src.timeline_url.startswith("clickhouse://"):
            manifest["databases"]["timeline"] = clickhouse_backup(src.timeline_url, name, clickhouse_target)
        else:
            raise BackupError("unsupported timeline url")
        timings["timeline"] = time.perf_counter() - t
        # audit log and job state
        t = time.perf_counter()
        for fname in ("audit.db", "jobs.db"):
            p = src.data_dir / fname
            if p.exists():
                sqlite_online_backup(p, stage / SQLITE_FILES[fname] / fname)
                manifest["databases"][fname.split(".")[0]] = {"engine": "sqlite", "file": f"{SQLITE_FILES[fname]}/{fname}"}
        timings["audit_jobs"] = time.perf_counter() - t
        # custody ledgers, anchors, keys, reports
        t = time.perf_counter()
        ledgers = _copy_tree(src.data_dir / "ledgers", stage / "ledgers", set())
        exclude = set() if include_master_key else {"master.key"}
        keys = _copy_tree(src.data_dir / "keys", stage / "keys", exclude)
        reports = _copy_tree(src.data_dir / "reports", stage / "reports", set())
        timings["ledgers_keys_reports"] = time.perf_counter() - t
        # evidence store manifest (inventory and hashes only)
        t = time.perf_counter()
        if src.store_backend == "s3":
            store = s3_store_manifest(src.s3_bucket or "veritas-evidence")
        else:
            store = local_store_manifest(src.data_dir / "store")
        (stage / "store-manifest.json").write_text(json.dumps(store, indent=1, sort_keys=True), encoding="utf-8")
        timings["store_manifest"] = time.perf_counter() - t
        # file manifest
        for p in iter_files(stage):
            rel = p.relative_to(stage).as_posix()
            manifest["files"][rel] = {"sha256": sha256_file(p), "size": p.stat().st_size}
        manifest["counts"] = {"ledgers": len([f for f in manifest["files"] if f.startswith("ledgers/") and not f.endswith(".anchors.jsonl")]),
                              "anchor_files": len([f for f in manifest["files"] if f.endswith(".anchors.jsonl")]), "ledger_files": ledgers, "key_files": keys,
                              "report_files": reports, "store_objects": store["object_count"], "store_plaintext_bytes": store["plaintext_bytes"]}
        manifest["master_key_included"] = include_master_key
        (stage / "MANIFEST.json").write_text(json.dumps(manifest, indent=1, sort_keys=True), encoding="utf-8")
        (stage / "MANIFEST.sha256").write_text(sha256_file(stage / "MANIFEST.json") + "  MANIFEST.json\n", encoding="utf-8")
        # tar + encrypt
        t = time.perf_counter()
        tar_path = work / "a.tar.gz"
        with tarfile.open(tar_path, "w:gz", compresslevel=6) as tf:
            for p in iter_files(stage):
                tf.add(p, arcname=f"{name}/{p.relative_to(stage).as_posix()}", recursive=False, filter=_tar_filter)
        archive = out_dir / f"{name}.vbk"
        tmp_archive = archive.with_suffix(".vbk.partial")
        with open(tar_path, "rb") as fin, open(tmp_archive, "wb") as fout:
            encrypt_stream(fin, fout, recipient)
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp_archive, archive)
        digest = sha256_file(archive)
        archive.with_suffix(".vbk.sha256").write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
        timings["archive_encrypt"] = time.perf_counter() - t
        timings["total"] = time.perf_counter() - t_all
        return BackupResult(archive, digest, manifest, {k: round(v, 3) for k, v in timings.items()})
    finally:
        shutil.rmtree(work, ignore_errors=True)


def read_archive(archive: Path, identity: PrivateKey) -> io.BytesIO:
    """Decrypt an archive into memory (used by restore and by tests); returns the tar.gz bytes."""
    buf = io.BytesIO()
    with open(archive, "rb") as fh:
        decrypt_stream(fh, buf, identity)
    buf.seek(0)
    return buf


# --------------------------------------------------------------------------- shipping and metrics
def upload(result: BackupResult, url: str) -> list[str]:
    """Copy the archive and its sidecar to ``s3://bucket/prefix`` (bucket default encryption and Object Lock apply)."""
    import boto3

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "s3" or not parsed.netloc:
        raise BackupError(f"--upload must be s3://bucket/prefix, got {url}")
    prefix = parsed.path.strip("/")
    s3 = boto3.client("s3", endpoint_url=os.environ.get("BACKUP_S3_ENDPOINT_URL") or None)
    keys = []
    for f in (result.archive, result.archive.with_suffix(".vbk.sha256")):
        key = f"{prefix}/{f.name}" if prefix else f.name
        extra: dict[str, Any] = {"ChecksumAlgorithm": "SHA256"}
        if f.suffix == ".vbk":
            extra["Metadata"] = {"veritas-archive-sha256": result.archive_sha256}
        s3.upload_file(str(f), parsed.netloc, key, ExtraArgs=extra)
        keys.append(f"s3://{parsed.netloc}/{key}")
    return keys


def push_metrics(gateway: str, ok: bool, duration_s: float, size_bytes: int, objects: int) -> None:
    """Publish the backup outcome to a Prometheus Pushgateway (alert: VeritasBackupFailed)."""
    from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

    reg = CollectorRegistry()
    Gauge("veritas_backup_last_status", "1 if the last backup succeeded, 0 otherwise", registry=reg).set(1 if ok else 0)
    Gauge("veritas_backup_last_run_timestamp_seconds", "Unix time of the last backup attempt", registry=reg).set_to_current_time()
    Gauge("veritas_backup_duration_seconds", "Duration of the last backup attempt", registry=reg).set(duration_s)
    if ok:
        Gauge("veritas_backup_last_success_timestamp_seconds", "Unix time of the last successful backup", registry=reg).set_to_current_time()
        Gauge("veritas_backup_size_bytes", "Size of the last encrypted backup archive", registry=reg).set(size_bytes)
        Gauge("veritas_backup_store_objects", "Evidence objects listed in the last backup manifest", registry=reg).set(objects)
    push_to_gateway(gateway, job="veritas-backup", registry=reg)


# --------------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="veritas-backup", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen", help="generate a recovery X25519 key pair (<out>.pub, <out>.key)")
    kg.add_argument("--out", required=True)
    cr = sub.add_parser("create", help="create an encrypted backup archive")
    cr.add_argument("--data-dir")
    cr.add_argument("--out", required=True, help="directory receiving the .vbk archive")
    g = cr.add_mutually_exclusive_group()
    g.add_argument("--recipient", help="file holding the recovery public key (hex)")
    g.add_argument("--recipient-hex", help="recovery public key as hex")
    cr.add_argument("--include-master-key", action="store_true")
    cr.add_argument("--work-dir", help="directory for plaintext staging (default: the output directory)")
    cr.add_argument("--upload", help="s3://bucket/prefix receiving the archive and its .sha256 sidecar")
    cr.add_argument("--keep-local", action="store_true", help="keep the local archive after a successful upload")
    cr.add_argument("--pushgateway", default=os.environ.get("VERITAS_PUSHGATEWAY_URL"), help="Prometheus Pushgateway URL for job metrics")
    cr.add_argument("--clickhouse-target", help="ClickHouse backup destination, e.g. \"S3('https://.../ch/', 'id', 'secret')\"")
    args = ap.parse_args(argv)

    if args.cmd == "keygen":
        pub, key = keygen(Path(args.out))
        print(json.dumps({"public_key_file": str(pub), "private_key_file": str(key), "public_key": pub.read_text(encoding="utf-8").strip()}))
        return 0
    spec = args.recipient_hex or args.recipient or os.environ.get("VERITAS_BACKUP_RECIPIENT")
    if not spec:
        print("a recovery public key is required (--recipient, --recipient-hex or VERITAS_BACKUP_RECIPIENT)", file=sys.stderr)
        return 2
    t0 = time.perf_counter()
    try:
        result = create_backup(Sources.from_env(args.data_dir), Path(args.out).resolve(), load_public_key(spec), args.include_master_key, args.clickhouse_target,
                               work_dir=Path(args.work_dir).resolve() if args.work_dir else None)
        summary = result.summary()
        if args.upload:
            summary["uploaded"] = upload(result, args.upload)
            if not args.keep_local:
                result.archive.unlink()
                result.archive.with_suffix(".vbk.sha256").unlink()
    except Exception as exc:  # any failure must reach the Pushgateway before the job exits non-zero
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
        if args.pushgateway:
            push_metrics(args.pushgateway, False, time.perf_counter() - t0, 0, 0)
        return 1
    if args.pushgateway:
        push_metrics(args.pushgateway, True, time.perf_counter() - t0, summary.get("archive_size", 0), summary["store_objects"])
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
