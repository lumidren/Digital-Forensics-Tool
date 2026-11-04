"""Decryption adapters for encrypted volumes.

Each adapter streams the decrypted volume to an output file in 4 MiB blocks and returns a
:class:`DecryptResult` with the output path and its SHA-256, so the Rust file-system parsers
(``veritas-fs``) can then work on plain bytes.

* BitLocker / BitLocker To Go: ``pybde`` (password, recovery password or startup key file).
* LUKS1: ``pyluksde`` (password or key file).
* LUKS2: ``pyluksde`` when it can open the header, otherwise a built-in implementation of the
  LUKS2 key-slot unlock (Argon2i/Argon2id/PBKDF2, anti-forensic merge, AES-CBC-plain / AES-XTS-plain64)
  using ``cryptography``.
* Encrypted APFS: ``pyfsapfs`` cannot export a decrypted block device, so the adapter unlocks the
  volume and extracts the file tree into an output directory plus a sorted ``manifest.jsonl``
  (path, size, sha256); the result's ``sha256`` is the hash of that manifest.

Credentials are never logged or written to output.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Callable, Iterable

BLOCK_SIZE = 4 * 1024 * 1024
#: Largest single APFS file extracted by :func:`decrypt_apfs`.
MAX_APFS_FILE = 4 * 1024 * 1024 * 1024
#: Maximum APFS directory depth walked.
MAX_APFS_DEPTH = 128
#: Upper bound for the LUKS2 JSON area accepted.
MAX_LUKS2_JSON = 4 * 1024 * 1024

APFS_GPT_TYPE = "7c3457ef-0000-11aa-aa11-00306543ecac"


class DecryptError(Exception):
    """Unlock or decryption failed (wrong credential, unsupported scheme, malformed header)."""


@dataclass
class DecryptResult:
    output_path: str
    sha256: str
    size: int
    method: str
    details: dict = field(default_factory=dict)


class _OffsetFile:
    """File-like window over ``[offset, offset + size)`` of another file (for libyal file objects)."""

    def __init__(self, f: BinaryIO, offset: int, size: int):
        self._f, self._off, self._size, self._pos = f, offset, size, 0

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = self._size - self._pos
        n = max(0, min(n, self._size - self._pos))
        self._f.seek(self._off + self._pos)
        d = self._f.read(n)
        self._pos += len(d)
        return d

    def seek(self, off: int, whence: int = os.SEEK_SET) -> int:
        base = {os.SEEK_SET: 0, os.SEEK_CUR: self._pos, os.SEEK_END: self._size}[whence]
        self._pos = max(0, base + off)
        return self._pos

    def tell(self) -> int:
        return self._pos

    def get_size(self) -> int:
        return self._size

    def get_offset(self) -> int:
        return self._pos

    def close(self) -> None:  # the underlying file is owned by the caller
        pass


def _stream_to_file(read_at: Callable[[int, int], bytes], size: int, output: str) -> tuple[str, int]:
    h = hashlib.sha256()
    written = 0
    os.makedirs(os.path.dirname(os.path.abspath(output)) or ".", exist_ok=True)
    with open(output, "wb") as out:
        while written < size:
            n = min(BLOCK_SIZE, size - written)
            data = read_at(written, n)
            if len(data) != n:
                raise DecryptError(f"short read at offset {written}: {len(data)} of {n} bytes")
            out.write(data)
            h.update(data)
            written += n
    return h.hexdigest(), written


def _libyal_read_at(vol) -> Callable[[int, int], bytes]:
    def read_at(off: int, n: int) -> bytes:
        return vol.read_buffer_at_offset(n, off)

    return read_at


# --------------------------------------------------------------------------------------------
# BitLocker


def decrypt_bitlocker(image: str, output: str, *, password: str | None = None, recovery_password: str | None = None,
                      startup_key: str | None = None, offset: int = 0, size: int | None = None) -> DecryptResult:
    """Decrypt a BitLocker (or BitLocker To Go) volume starting at ``offset`` of ``image``."""
    import pybde

    if not (password or recovery_password or startup_key):
        raise DecryptError("BitLocker needs a password, recovery password or startup key")
    with open(image, "rb") as f:
        total = size if size is not None else os.path.getsize(image) - offset
        fobj = _OffsetFile(f, offset, total)
        if not pybde.check_volume_signature_file_object(fobj):
            raise DecryptError("no BitLocker signature")
        vol = pybde.volume()
        if password:
            vol.set_password(password)
        if recovery_password:
            vol.set_recovery_password(recovery_password)
        if startup_key:
            vol.read_startup_key(startup_key)
        try:
            vol.open_file_object(fobj)
        except OSError as e:
            raise DecryptError(f"unable to open BitLocker volume: {e}") from e
        try:
            if vol.is_locked() and not vol.unlock():
                raise DecryptError("BitLocker unlock failed (wrong credential)")
            vsize = vol.get_size()
            sha, n = _stream_to_file(_libyal_read_at(vol), vsize, output)
            method = "password" if password else ("recovery_password" if recovery_password else "startup_key")
            return DecryptResult(output, sha, n, f"bitlocker:{method}", {"encryption_method": vol.get_encryption_method()})
        finally:
            vol.close()


# --------------------------------------------------------------------------------------------
# LUKS


def _luks_version(image: str, offset: int) -> int:
    with open(image, "rb") as f:
        f.seek(offset)
        hdr = f.read(8)
    if hdr[:6] != b"LUKS\xba\xbe":
        raise DecryptError("no LUKS signature")
    return struct.unpack(">H", hdr[6:8])[0]


def decrypt_luks(image: str, output: str, *, password: str | None = None, key_file: str | None = None,
                 offset: int = 0) -> DecryptResult:
    """Decrypt a LUKS1 or LUKS2 volume. ``key_file`` content is used as the passphrase bytes."""
    if not (password or key_file):
        raise DecryptError("LUKS needs a password or key file")
    secret = password.encode("utf-8") if password else open(key_file, "rb").read()
    version = _luks_version(image, offset)
    import pyluksde

    with open(image, "rb") as f:
        fobj = _OffsetFile(f, offset, os.path.getsize(image) - offset)
        vol = pyluksde.volume()
        if password:
            vol.set_password(password)
        else:
            vol.set_key(secret) if hasattr(vol, "set_key") else vol.set_password(secret.decode("latin-1"))
        try:
            vol.open_file_object(fobj)
        except OSError as e:
            if version == 2:
                return _luks2_decrypt(image, output, secret, offset)
            raise DecryptError(f"unable to open LUKS volume: {e}") from e
        try:
            if vol.is_locked():
                raise DecryptError("LUKS unlock failed (wrong credential)")
            sha, n = _stream_to_file(_libyal_read_at(vol), vol.get_size(), output)
            return DecryptResult(output, sha, n, f"luks{version}:pyluksde")
        finally:
            vol.close()


def _af_merge(material: bytes, key_size: int, stripes: int, hash_name: str) -> bytes:
    """LUKS anti-forensic merge (inverse of AF split)."""

    def diffuse(buf: bytes) -> bytes:
        hl = hashlib.new(hash_name).digest_size
        out = bytearray()
        for i in range((len(buf) + hl - 1) // hl):
            chunk = buf[i * hl:(i + 1) * hl]
            out += hashlib.new(hash_name, struct.pack(">I", i) + chunk).digest()[:len(chunk)]
        return bytes(out)

    d = bytes(key_size)
    for i in range(stripes - 1):
        block = material[i * key_size:(i + 1) * key_size]
        d = diffuse(bytes(a ^ b for a, b in zip(d, block)))
    last = material[(stripes - 1) * key_size:stripes * key_size]
    return bytes(a ^ b for a, b in zip(d, last))


def _sector_cipher(spec: str, key: bytes, sector_size: int, iv_tweak: int = 0) -> Callable[[bytes, int], bytes]:
    """Return ``decrypt(data, first_sector)`` for ``aes-cbc-plain``, ``aes-cbc-plain64`` or ``aes-xts-plain64``."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    spec = spec.lower()
    if spec.startswith("aes-xts-plain"):
        def dec(data: bytes, first: int) -> bytes:
            out = bytearray()
            for i in range(0, len(data), sector_size):
                tweak = (first + iv_tweak + i // sector_size).to_bytes(16, "little")
                d = Cipher(algorithms.AES(key), modes.XTS(tweak)).decryptor()
                out += d.update(data[i:i + sector_size]) + d.finalize()
            return bytes(out)
        return dec
    if spec in ("aes-cbc-plain", "aes-cbc-plain64"):
        width = 4 if spec == "aes-cbc-plain" else 8

        def dec(data: bytes, first: int) -> bytes:
            out = bytearray()
            for i in range(0, len(data), sector_size):
                n = (first + iv_tweak + i // sector_size) & ((1 << (8 * width)) - 1)
                iv = n.to_bytes(width, "little").ljust(16, b"\0")
                d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                out += d.update(data[i:i + sector_size]) + d.finalize()
            return bytes(out)
        return dec
    raise DecryptError(f"unsupported LUKS cipher spec {spec!r}")


def _luks2_kdf(kdf: dict, secret: bytes, key_size: int) -> bytes:
    salt = base64.b64decode(kdf["salt"])
    t = kdf["type"]
    if t == "pbkdf2":
        return hashlib.pbkdf2_hmac(kdf["hash"], secret, salt, int(kdf["iterations"]), key_size)
    if t in ("argon2i", "argon2id"):
        from cryptography.hazmat.primitives.kdf import argon2

        cls = argon2.Argon2i if t == "argon2i" else argon2.Argon2id
        return cls(salt=salt, length=key_size, iterations=int(kdf["time"]), lanes=int(kdf["cpus"]),
                   memory_cost=int(kdf["memory"])).derive(secret)
    raise DecryptError(f"unsupported LUKS2 KDF {t!r}")


def luks2_unlock(image: str, secret: bytes, offset: int = 0) -> tuple[bytes, dict]:
    """Recover the LUKS2 volume key. Returns (key, segment dict). Raises DecryptError on a wrong secret."""
    with open(image, "rb") as f:
        f.seek(offset)
        hdr = f.read(4096)
        hdr_size = struct.unpack(">Q", hdr[8:16])[0]
        if not 4096 < hdr_size <= MAX_LUKS2_JSON + 4096:
            raise DecryptError("implausible LUKS2 header size")
        f.seek(offset + 4096)
        meta = json.loads(f.read(hdr_size - 4096).split(b"\0", 1)[0])
        for dg in meta["digests"].values():
            for ks_id in dg["keyslots"]:
                ks = meta["keyslots"][ks_id]
                area, af = ks["area"], ks["af"]
                key_size = int(ks["key_size"])
                area_key = _luks2_kdf(ks["kdf"], secret, int(area["key_size"]))
                f.seek(offset + int(area["offset"]))
                enc = f.read(key_size * int(af["stripes"]))
                enc += bytes((-len(enc)) % 512)
                material = _sector_cipher(area["encryption"], area_key, 512)(enc, 0)
                key = _af_merge(material, key_size, int(af["stripes"]), af["hash"])
                if dg["type"] != "pbkdf2":
                    raise DecryptError(f"unsupported LUKS2 digest {dg['type']!r}")
                want = base64.b64decode(dg["digest"])
                got = hashlib.pbkdf2_hmac(dg["hash"], key, base64.b64decode(dg["salt"]), int(dg["iterations"]), len(want))
                if got == want:
                    seg = meta["segments"][dg["segments"][0]]
                    return key, seg
    raise DecryptError("LUKS2 unlock failed (wrong credential)")


def _luks2_decrypt(image: str, output: str, secret: bytes, offset: int) -> DecryptResult:
    key, seg = luks2_unlock(image, secret, offset)
    if seg.get("type") != "crypt":
        raise DecryptError(f"unsupported LUKS2 segment type {seg.get('type')!r}")
    sector = int(seg.get("sector_size", 512))
    seg_off = offset + int(seg["offset"])
    total = os.path.getsize(image)
    size = max(0, total - seg_off) if seg["size"] == "dynamic" else int(seg["size"])
    dec = _sector_cipher(seg["encryption"], key, sector, int(seg.get("iv_tweak", "0")))
    with open(image, "rb") as f:
        def read_at(off: int, n: int) -> bytes:
            f.seek(seg_off + off)
            data = f.read(n)
            return dec(data, off // sector)

        sha, n = _stream_to_file(read_at, size - size % sector, output)
    return DecryptResult(output, sha, n, "luks2:builtin", {"segment_offset": int(seg["offset"]), "sector_size": sector})


# --------------------------------------------------------------------------------------------
# APFS


def find_apfs_container(image: str) -> tuple[int, int]:
    """Locate an APFS container: bare (NXSB at offset 32) or as a GPT partition. Returns (offset, size)."""
    size = os.path.getsize(image)
    with open(image, "rb") as f:
        head = f.read(4096)
        if head[32:36] == b"NXSB":
            return 0, size
        for ss in (512, 4096):
            f.seek(ss)
            h = f.read(92)
            if h[:8] != b"EFI PART":
                continue
            entries_lba, count, esize = struct.unpack("<QII", h[72:88])
            if not 128 <= esize <= 4096 or count > 4096:
                raise DecryptError("implausible GPT entry array")
            f.seek(entries_lba * ss)
            arr = f.read(count * esize)
            for i in range(count):
                e = arr[i * esize:(i + 1) * esize]
                tg = e[:16]
                guid = "%08x-%04x-%04x-%s-%s" % (struct.unpack("<I", tg[:4])[0], struct.unpack("<H", tg[4:6])[0],
                                                 struct.unpack("<H", tg[6:8])[0], tg[8:10].hex(), tg[10:16].hex())
                if guid == APFS_GPT_TYPE:
                    first, last = struct.unpack("<QQ", e[32:48])
                    return first * ss, (last - first + 1) * ss
    raise DecryptError("no APFS container found")


def _apfs_volumes(image: str, f: BinaryIO, password: str | None, recovery_password: str | None):
    import pyfsapfs

    off, size = find_apfs_container(image)
    c = pyfsapfs.container()
    try:
        c.open_file_object(_OffsetFile(f, off, size))
    except OSError as e:
        raise DecryptError(f"unable to open APFS container: {e}") from e
    vols = []
    for i in range(c.number_of_volumes):
        v = c.get_volume(i)
        if v.is_locked():
            if password:
                v.set_password(password)
            if recovery_password:
                v.set_recovery_password(recovery_password)
            if not v.unlock():
                raise DecryptError(f"APFS volume {v.name!r} unlock failed (wrong credential)")
        vols.append(v)
    return c, vols


def _walk_apfs(entry, prefix: str, depth: int = 0) -> Iterable[tuple[str, object]]:
    if depth > MAX_APFS_DEPTH:
        return
    for i in range(entry.number_of_sub_file_entries):
        sub = entry.get_sub_file_entry(i)
        path = f"{prefix}/{sub.name}"
        yield path, sub
        if (sub.file_mode & 0o170000) == 0o040000:
            yield from _walk_apfs(sub, path, depth + 1)


def list_apfs(image: str, *, password: str | None = None, recovery_password: str | None = None) -> list[str]:
    """Sorted paths of every entry in every (unlocked) APFS volume (volume name prefix when >1)."""
    with open(image, "rb") as f:
        _, vols = _apfs_volumes(image, f, password, recovery_password)
        out: list[Any] = []
        for v in vols:
            pre = f"/{v.name}" if len(vols) > 1 else ""
            out.extend(pre + p for p, _ in _walk_apfs(v.get_root_directory(), ""))
        return sorted(out)


def _safe_component(name: str) -> str:
    bad = '<>:"/\\|?*%'
    s = "".join(f"%{ord(c):02X}" if (c in bad or ord(c) < 0x20) else c for c in name)
    if s in ("", ".", ".."):
        s = s.replace(".", "%2E") or "%00"
    return s


def decrypt_apfs(image: str, output_dir: str, *, password: str | None = None,
                 recovery_password: str | None = None) -> DecryptResult:
    """Unlock encrypted APFS volumes and extract regular files under ``output_dir``."""
    if not (password or recovery_password):
        raise DecryptError("encrypted APFS needs a password or recovery password")
    os.makedirs(output_dir, exist_ok=True)
    root = os.path.abspath(output_dir)
    manifest = []
    with open(image, "rb") as f:
        _, vols = _apfs_volumes(image, f, password, recovery_password)
        for v in vols:
            pre = f"/{v.name}" if len(vols) > 1 else ""
            e: Any
            for path, e in _walk_apfs(v.get_root_directory(), pre):
                mode = e.file_mode & 0o170000
                rec = {"path": path, "identifier": e.identifier, "size": e.size, "mode": e.file_mode}
                if mode == 0o100000 and e.size <= MAX_APFS_FILE:
                    target = os.path.join(root, *[_safe_component(c) for c in path.split("/") if c])
                    if os.path.commonpath([root, os.path.abspath(target)]) != root:
                        raise DecryptError(f"refusing to write outside output dir: {path!r}")
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    h = hashlib.sha256()
                    with open(target, "wb") as out:
                        pos = 0
                        while pos < e.size:
                            d = e.read_buffer_at_offset(min(BLOCK_SIZE, e.size - pos), pos)
                            if not d:
                                break
                            out.write(d)
                            h.update(d)
                            pos += len(d)
                    rec["sha256"] = h.hexdigest()
                manifest.append(rec)
    manifest.sort(key=lambda r: r["path"])
    blob = "".join(json.dumps(r, sort_keys=True) + "\n" for r in manifest).encode()
    with open(os.path.join(root, "manifest.jsonl"), "wb") as m:
        m.write(blob)
    return DecryptResult(root, hashlib.sha256(blob).hexdigest(), len(blob), "apfs:pyfsapfs", {"entries": len(manifest)})


__all__ = [
    "DecryptError",
    "DecryptResult",
    "decrypt_bitlocker",
    "decrypt_luks",
    "decrypt_apfs",
    "list_apfs",
    "luks2_unlock",
    "find_apfs_container",
]
