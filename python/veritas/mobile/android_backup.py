"""Android ``adb backup`` (``.ab``) archives and ``adb pull`` directory trees.

``.ab`` layout::

    ANDROID BACKUP\\n
    <version>\\n          1..5
    <compressed>\\n       0 or 1 (zlib deflate stream)
    <encryption>\\n       "none" (supported) or "AES-256" (refused: out of scope)
    <tar stream>

The payload is inflated incrementally and read as a streaming tar (``tarfile`` mode ``r|``), so the
archive is never fully materialised. Known databases are handed to :mod:`veritas.mobile.android_db`.
"""
from __future__ import annotations

import io
import os
import tarfile
import zlib
from dataclasses import dataclass
from typing import Any, BinaryIO

from veritas.timeline.schema import Desc

from . import android_db
from veritas.cloud.base import apply_provenance, provenance_fields

from .common import ParseResult, ParserError, guard, make_event, s_to_ns, source_name

MAGIC = b"ANDROID BACKUP\n"
MAX_MEMBER_BYTES = 512 * 1024 * 1024
CHUNK = 64 * 1024
DATA_TYPE_FILE = "android:backup:file"
DATA_TYPE_APP = "android:app:package"


@dataclass(frozen=True, slots=True)
class AbHeader:
    version: int
    compressed: bool
    encryption: str
    payload_offset: int


def _readline(fh: BinaryIO, limit: int = 256) -> bytes:
    line = fh.readline(limit)
    if not line.endswith(b"\n"):
        raise ParserError("truncated .ab header")
    return line[:-1]


def read_header(fh: BinaryIO) -> AbHeader:
    magic = fh.read(len(MAGIC))
    if magic != MAGIC:
        raise ParserError("not an Android backup (missing 'ANDROID BACKUP' magic)")
    try:
        version = int(_readline(fh).decode("ascii"))
        compressed_flag = int(_readline(fh).decode("ascii"))
        encryption = _readline(fh).decode("ascii")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ParserError(f"malformed .ab header: {exc}") from exc
    if version < 1 or version > 10:
        raise ParserError(f"unsupported .ab version {version}")
    if compressed_flag not in (0, 1):
        raise ParserError(f"invalid .ab compression flag {compressed_flag}")
    if encryption.lower() != "none":
        raise ParserError(
            f"encrypted Android backup ({encryption}): decryption of password-protected backups is out of scope; "
            "re-create the backup without a password or decrypt it with the examiner's tooling first"
        )
    return AbHeader(version=version, compressed=bool(compressed_flag), encryption=encryption, payload_offset=fh.tell())


class _InflateReader(io.RawIOBase):
    """File-like object inflating a zlib stream on demand (bounded output per step)."""

    def __init__(self, fh: BinaryIO) -> None:
        self._fh = fh
        self._z = zlib.decompressobj()
        self._pending = b""
        self._buf = b""
        self._eof = False

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        while not self._buf and not self._eof:
            data = self._pending or self._fh.read(CHUNK)
            if not data:
                self._eof = True
                break
            try:
                self._buf = self._z.decompress(data, CHUNK * 16)
            except zlib.error as exc:
                raise ParserError(f"corrupt .ab zlib stream: {exc}") from exc
            self._pending = self._z.unconsumed_tail
            if self._z.eof:
                self._eof = True
        n = min(len(b), len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n


def _manifest_fields(data: bytes) -> dict[str, Any]:
    lines = data.decode("utf-8", errors="replace").split("\n")
    names = ("manifest_version", "package", "version_code", "platform_version", "installer_package", "has_apk")
    out: dict[str, Any] = {}
    for name, value in zip(names, lines):
        out[name] = value
    return out


def _parse_member(name: str, data: bytes, result: ParseResult, ev_path: str, sha: str) -> None:
    fn = android_db.parser_for(name)
    if fn is None:
        return
    try:
        sub = fn(data, evidence_path=f"{ev_path}!{name}", evidence_sha256=sha)
    except ParserError as exc:
        result.warn(f"{name}: {exc}")
        return
    result.extend(sub)


def parse_ab(source, *, evidence_path: str = "", evidence_sha256: str = "", file_events: bool = True) -> ParseResult:
    ev_path = evidence_path or source_name(source)
    result = ParseResult()
    with guard(".ab backup"):
        if isinstance(source, (bytes, bytearray, memoryview)):
            fh: BinaryIO = io.BytesIO(bytes(source))
            close = False
        else:
            try:
                fh = open(source, "rb")
            except OSError as exc:
                raise ParserError(f"cannot read {ev_path}: {exc}") from exc
            close = True
        try:
            header = read_header(fh)
            stream: BinaryIO = io.BufferedReader(_InflateReader(fh), CHUNK) if header.compressed else fh
            result.events.append(make_event(
                data_type="android:backup:header", timestamp_desc=Desc.NOT_A_TIME,
                message=f"Android backup v{header.version} compressed={header.compressed} encryption={header.encryption}",
                timestamp=None, source_short="ANDROID", source_long="Android adb backup", parser="android_ab",
                evidence_path=ev_path, evidence_sha256=evidence_sha256, offset=0,
                attrs={"version": header.version, "compressed": header.compressed, "encryption": header.encryption},
            ))
            try:
                tar = tarfile.open(fileobj=stream, mode="r|")
            except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
                raise ParserError(f".ab payload is not a tar stream: {exc}") from exc
            members = 0
            try:
                for index, member in enumerate(tar):
                    members += 1
                    name = member.name.replace("\\", "/")
                    if member.isfile() and file_events:
                        result.events.append(make_event(
                            data_type=DATA_TYPE_FILE, timestamp_desc=Desc.MODIFICATION,
                            message=f"Backup file {name} ({member.size} bytes)", timestamp=s_to_ns(member.mtime),
                            source_short="ANDROID", source_long="Android adb backup", parser="android_ab",
                            evidence_path=f"{ev_path}!{name}", evidence_sha256=evidence_sha256, offset=index,
                            timezone="UTC",
                            attrs={"path": name, "size": member.size, "mode": oct(member.mode),
                                   "package": name.split("/")[1] if name.startswith("apps/") and name.count("/") >= 2 else None},
                        ))
                    if not member.isfile():
                        continue
                    base = name.rsplit("/", 1)[-1]
                    wanted = android_db.parser_for(name) is not None or base == "_manifest"
                    if not wanted:
                        continue
                    if member.size > MAX_MEMBER_BYTES:
                        result.warn(f"{name}: member too large ({member.size} bytes), skipped")
                        continue
                    fobj = tar.extractfile(member)
                    data = fobj.read() if fobj is not None else b""
                    if len(data) != member.size:
                        result.warn(f"{name}: truncated member ({len(data)} of {member.size} bytes)")
                        break
                    if base == "_manifest":
                        fields = _manifest_fields(data)
                        result.events.append(make_event(
                            data_type=DATA_TYPE_APP, timestamp_desc=Desc.NOT_A_TIME,
                            message=f"Backed-up app {fields.get('package') or '?'} versionCode {fields.get('version_code') or '?'}",
                            timestamp=None, source_short="ANDROID", source_long="Android adb backup manifest",
                            parser="android_ab", evidence_path=f"{ev_path}!{name}", evidence_sha256=evidence_sha256,
                            offset=index, attrs=fields,
                        ))
                    else:
                        _parse_member(name, data, result, ev_path, evidence_sha256)
            except (tarfile.TarError, EOFError, zlib.error, OSError, ParserError) as exc:
                result.warn(f"tar stream ended abnormally after {members} members: {exc}")
            if members == 0:
                raise ParserError(".ab payload contains no tar members")
        finally:
            if close:
                fh.close()
    return result


def parse_directory(root: str | os.PathLike[str], *, evidence_sha256: str = "") -> ParseResult:
    """ADB-pull / extracted-backup mode: parse every known database below ``root``."""
    result = ParseResult()
    with guard("android directory"):
        if not os.path.isdir(root):
            raise ParserError(f"not a directory: {source_name(root)}")
        found = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for fname in sorted(filenames):
                fn = android_db.parser_for(fname)
                if fn is None:
                    continue
                full = os.path.join(dirpath, fname)
                rel = os.path.relpath(full, root).replace("\\", "/")
                found += 1
                try:
                    result.extend(fn(full, evidence_path=rel, evidence_sha256=evidence_sha256))
                except ParserError as exc:
                    result.warn(f"{rel}: {exc}")
        if not found:
            raise ParserError("no known Android databases found in directory")
    return result


def parse(source, provenance=None, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    """Pipeline entry point: an ``.ab`` file or an ``adb pull`` directory.

    ``provenance`` is a ``veritas.parsers.base.Provenance`` (or any object exposing
    ``evidence_sha256`` / ``evidence_path``). Iterating the returned result yields Events.
    """
    evidence_path, evidence_sha256 = provenance_fields(provenance, evidence_path, evidence_sha256)
    if isinstance(source, (str, os.PathLike)) and os.path.isdir(source):
        result = parse_directory(source, evidence_sha256=evidence_sha256)
    else:
        result = parse_ab(source, evidence_path=evidence_path, evidence_sha256=evidence_sha256)
    return apply_provenance(result, provenance)
