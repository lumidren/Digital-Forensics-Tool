"""Content-addressed evidence store (Python side).

``LocalStore`` uses the same on-disk layout and encryption framing as ``crates/veritas-store``:

* ``objects/<aa>/<bb>/<sha256>`` holds the object, ``meta/<sha256>.json`` its metadata;
* committed files are made read-only and never overwritten (WORM semantics);
* with a master key, the plaintext is split into 1 MiB frames, each sealed with
  XChaCha20-Poly1305 under ``sha256(master || "veritas-case-dek" || case_id)``, nonce = frame
  index (u64 LE) padded to 24 bytes, associated data = case id, and written as ``u32 LE length ||
  ciphertext``.

Objects written by either implementation are readable by the other; ``tests/unit/test_store.py``
checks this against the Rust ``veritas`` CLI when it is built.

``S3Store`` (cluster profile) writes to a bucket that must have Object Lock enabled in compliance
mode; the constructor refuses to run against a bucket without it.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO, Iterator, Protocol

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt, crypto_aead_xchacha20poly1305_ietf_encrypt

FRAME_SIZE = 1 << 20
TAG_SIZE = 16


class StoreError(Exception):
    pass


class CorruptObject(StoreError):
    pass


@dataclass(slots=True)
class Hashes:
    md5: str
    sha256: str
    sha3_256: str
    length: int


@dataclass(slots=True)
class ObjectMeta:
    address: str
    hashes: Hashes
    case_id: str
    encrypted: bool
    original_name: str | None = None
    content_type: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ObjectMeta":
        return cls(address=d["address"], hashes=Hashes(**d["hashes"]), case_id=d["case_id"], encrypted=d["encrypted"], original_name=d.get("original_name"), content_type=d.get("content_type"))


class MultiHasher:
    def __init__(self) -> None:
        self.md5 = hashlib.md5(usedforsecurity=False)
        self.sha256 = hashlib.sha256()
        self.sha3 = hashlib.sha3_256()
        self.length = 0

    def update(self, b: bytes) -> None:
        self.md5.update(b)
        self.sha256.update(b)
        self.sha3.update(b)
        self.length += len(b)

    def finalize(self) -> Hashes:
        return Hashes(self.md5.hexdigest(), self.sha256.hexdigest(), self.sha3.hexdigest(), self.length)


def hash_file(path: str | Path) -> Hashes:
    h = MultiHasher()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(4 << 20), b""):
            h.update(chunk)
    return h.finalize()


class CaseKeyring:
    def __init__(self, master_key: bytes):
        if len(master_key) != 32:
            raise ValueError("master key must be 32 bytes")
        self._master = master_key

    @classmethod
    def from_env(cls, var: str = "VERITAS_MASTER_KEY") -> "CaseKeyring | None":
        v = os.environ.get(var)
        return cls(bytes.fromhex(v)) if v else None

    def case_key(self, case_id: str) -> bytes:
        # THREAT:T4.1 one key per case, derived, never stored.
        return hashlib.sha256(self._master + b"veritas-case-dek" + case_id.encode("utf-8")).digest()


def _nonce(i: int) -> bytes:
    return i.to_bytes(8, "little") + b"\x00" * 16


def encrypt_frame(key: bytes, case_id: str, index: int, pt: bytes) -> bytes:
    return crypto_aead_xchacha20poly1305_ietf_encrypt(pt, case_id.encode("utf-8"), _nonce(index), key)


def decrypt_frame(key: bytes, case_id: str, index: int, ct: bytes) -> bytes:
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ct, case_id.encode("utf-8"), _nonce(index), key)
    except Exception as exc:
        raise CorruptObject("authentication failed (wrong case key or tampered ciphertext)") from exc


class DecryptingReader(io.RawIOBase):
    def __init__(self, fh: BinaryIO, key: bytes, case_id: str):
        self._fh, self._key, self._case = fh, key, case_id
        self._buf = b""
        self._idx = 0
        self._eof = False

    def readable(self) -> bool:
        return True

    def _fill(self) -> None:
        hdr = self._fh.read(4)
        if len(hdr) < 4:
            self._eof = True
            return
        n = int.from_bytes(hdr, "little")
        if n > FRAME_SIZE + TAG_SIZE:
            raise CorruptObject("frame length exceeds maximum")
        ct = self._fh.read(n)
        if len(ct) != n:
            raise CorruptObject("truncated frame")
        self._buf = decrypt_frame(self._key, self._case, self._idx, ct)
        self._idx += 1

    def readinto(self, b) -> int:
        while not self._buf and not self._eof:
            self._fill()
        n = min(len(b), len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n

    def close(self) -> None:
        self._fh.close()
        super().close()


class ContentStore(Protocol):
    def put(self, case_id: str, src: BinaryIO, original_name: str | None = None) -> ObjectMeta: ...
    def put_file(self, case_id: str, path: str | Path, original_name: str | None = None) -> ObjectMeta: ...
    def open(self, address: str) -> BinaryIO: ...
    def meta(self, address: str) -> ObjectMeta: ...
    def exists(self, address: str) -> bool: ...
    def list(self) -> list[str]: ...
    def verify(self, address: str) -> bool: ...


class LocalStore:
    def __init__(self, root: str | Path, keyring: CaseKeyring | None = None):
        self.root = Path(root)
        for d in ("objects", "meta", "tmp"):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        self.keyring = keyring

    def _obj(self, a: str) -> Path:
        return self.root / "objects" / a[:2] / a[2:4] / a

    def _meta(self, a: str) -> Path:
        return self.root / "meta" / f"{a}.json"

    @staticmethod
    def _readonly(p: Path) -> None:
        os.chmod(p, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

    def put(self, case_id: str, src: BinaryIO, original_name: str | None = None) -> ObjectMeta:
        tmp = self.root / "tmp" / f"{os.getpid()}-{secrets.token_hex(8)}"
        h = MultiHasher()
        key = self.keyring.case_key(case_id) if self.keyring else None
        idx = 0
        with open(tmp, "wb") as out:
            while True:
                chunk = src.read(FRAME_SIZE)
                while chunk and len(chunk) < FRAME_SIZE:
                    more = src.read(FRAME_SIZE - len(chunk))
                    if not more:
                        break
                    chunk += more
                if not chunk:
                    break
                h.update(chunk)
                if key:
                    ct = encrypt_frame(key, case_id, idx, chunk)
                    out.write(len(ct).to_bytes(4, "little"))
                    out.write(ct)
                else:
                    out.write(chunk)
                idx += 1
                if len(chunk) < FRAME_SIZE:
                    break
            out.flush()
            os.fsync(out.fileno())
        hashes = h.finalize()
        a = hashes.sha256
        final = self._obj(a)
        if final.exists():
            # THREAT:T1.3 write-once: never replace a committed object.
            tmp.unlink(missing_ok=True)
            existing = self.meta(a)
            if existing.hashes != hashes:
                raise StoreError(f"refusing to overwrite committed object {a}")
            return existing
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp, final)
        self._readonly(final)
        meta = ObjectMeta(a, hashes, case_id, key is not None, original_name)
        mp = self._meta(a)
        with open(mp, "x", encoding="utf-8") as fh:
            json.dump(meta.to_dict(), fh, indent=2)
        self._readonly(mp)
        return meta

    def put_file(self, case_id: str, path: str | Path, original_name: str | None = None) -> ObjectMeta:
        with open(path, "rb") as fh:
            return self.put(case_id, fh, original_name or Path(path).name)

    def meta(self, address: str) -> ObjectMeta:
        try:
            return ObjectMeta.from_dict(json.loads(self._meta(address).read_text(encoding="utf-8")))
        except FileNotFoundError as exc:
            raise StoreError(f"object {address} not found") from exc

    def exists(self, address: str) -> bool:
        return len(address) == 64 and self._obj(address).exists()

    def open(self, address: str) -> BinaryIO:
        m = self.meta(address)
        fh = open(self._obj(address), "rb")
        if m.encrypted:
            if not self.keyring:
                fh.close()
                raise StoreError("object is encrypted but no keyring is configured")
            return io.BufferedReader(DecryptingReader(fh, self.keyring.case_key(m.case_id), m.case_id), buffer_size=FRAME_SIZE)
        return fh

    def materialize(self, address: str, dest_dir: str | Path) -> Path:
        """Plaintext copy for tools that need a file path (parsers, Volatility). Caller deletes it."""
        m = self.meta(address)
        if not m.encrypted:
            return self._obj(address)
        dest = Path(dest_dir) / address
        with self.open(address) as src, open(dest, "wb") as out:
            for chunk in iter(lambda: src.read(FRAME_SIZE), b""):
                out.write(chunk)
        return dest

    def list(self) -> list[str]:
        return sorted(p.stem for p in (self.root / "meta").glob("*.json"))

    def verify(self, address: str) -> bool:
        m = self.meta(address)
        h = MultiHasher()
        try:
            with self.open(address) as fh:
                for chunk in iter(lambda: fh.read(FRAME_SIZE), b""):
                    h.update(chunk)
        except CorruptObject:
            return False
        return h.finalize() == m.hashes

    def iter_verify(self) -> Iterator[tuple[str, bool]]:
        for a in self.list():
            yield a, self.verify(a)


class S3Store:
    """S3 / MinIO backend. Requires Object Lock (compliance mode) on the bucket."""

    def __init__(self, bucket: str, keyring: CaseKeyring | None = None, retention_days: int = 3650, client=None, kms_key_id: str | None = None):
        import boto3  # cluster extra

        self.s3 = client or boto3.client("s3", endpoint_url=os.environ.get("S3_ENDPOINT_URL"))
        self.bucket = bucket
        self.keyring = keyring
        self.retention_days = retention_days
        self.kms_key_id = kms_key_id
        cfg = self.s3.get_object_lock_configuration(Bucket=bucket).get("ObjectLockConfiguration", {})
        if cfg.get("ObjectLockEnabled") != "Enabled":
            raise StoreError(f"bucket {bucket} does not have Object Lock enabled")  # THREAT:T1.3

    def _key(self, a: str) -> str:
        return f"objects/{a[:2]}/{a[2:4]}/{a}"

    def put_file(self, case_id: str, path: str | Path, original_name: str | None = None) -> ObjectMeta:
        from datetime import datetime, timedelta, timezone

        hashes = hash_file(path)
        a = hashes.sha256
        if self.exists(a):
            return self.meta(a)
        key = self.keyring.case_key(case_id) if self.keyring else None
        body: BinaryIO
        if key:
            buf = io.BytesIO()
            with open(path, "rb") as fh:
                for i, chunk in enumerate(iter(lambda: fh.read(FRAME_SIZE), b"")):
                    ct = encrypt_frame(key, case_id, i, chunk)
                    buf.write(len(ct).to_bytes(4, "little") + ct)
            buf.seek(0)
            body = buf
        else:
            body = open(path, "rb")
        meta = ObjectMeta(a, hashes, case_id, key is not None, original_name or Path(path).name)
        until = datetime.now(timezone.utc) + timedelta(days=self.retention_days)
        extra = {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": self.kms_key_id} if self.kms_key_id else {"ServerSideEncryption": "AES256"}
        try:
            self.s3.put_object(Bucket=self.bucket, Key=self._key(a), Body=body, ObjectLockMode="COMPLIANCE", ObjectLockRetainUntilDate=until, ChecksumAlgorithm="SHA256", **extra)
        finally:
            body.close()
        self.s3.put_object(Bucket=self.bucket, Key=f"meta/{a}.json", Body=json.dumps(meta.to_dict()).encode(), ObjectLockMode="COMPLIANCE", ObjectLockRetainUntilDate=until, **extra)
        return meta

    def put(self, case_id: str, src: BinaryIO, original_name: str | None = None) -> ObjectMeta:
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            for chunk in iter(lambda: src.read(FRAME_SIZE), b""):
                tmp.write(chunk)
        try:
            return self.put_file(case_id, tmp.name, original_name)
        finally:
            os.unlink(tmp.name)

    def meta(self, address: str) -> ObjectMeta:
        obj = self.s3.get_object(Bucket=self.bucket, Key=f"meta/{address}.json")
        return ObjectMeta.from_dict(json.loads(obj["Body"].read()))

    def exists(self, address: str) -> bool:
        try:
            self.s3.head_object(Bucket=self.bucket, Key=f"meta/{address}.json")
            return True
        except Exception:
            return False

    def open(self, address: str) -> BinaryIO:
        m = self.meta(address)
        body = self.s3.get_object(Bucket=self.bucket, Key=self._key(address))["Body"]
        if m.encrypted:
            if not self.keyring:
                raise StoreError("object is encrypted but no keyring is configured")
            return io.BufferedReader(DecryptingReader(body, self.keyring.case_key(m.case_id), m.case_id), buffer_size=FRAME_SIZE)
        return body

    def list(self) -> list[str]:
        out: list[str] = []
        for page in self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix="meta/"):
            out += [o["Key"][5:-5] for o in page.get("Contents", [])]
        return sorted(out)

    def verify(self, address: str) -> bool:
        m = self.meta(address)
        h = MultiHasher()
        with self.open(address) as fh:
            for chunk in iter(lambda: fh.read(FRAME_SIZE), b""):
                h.update(chunk)
        return h.finalize() == m.hashes
