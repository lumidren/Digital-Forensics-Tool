"""iTunes / Finder / ``idevicebackup2`` backup directories (iOS 10+ ``Manifest.db`` layout).

A backup directory holds ``Info.plist``, ``Manifest.plist``, ``Status.plist``, ``Manifest.db`` and
the file contents stored under ``<fileID[:2]>/<fileID>`` where ``fileID = sha1(domain-relativePath)``.

Encrypted backups (``IsEncrypted`` in Manifest.plist) are refused with a :class:`ParserError`:
decrypting the keybag requires the backup password and is out of scope (docs/MOBILE_SCOPE.md).
"""
from __future__ import annotations

import hashlib
import os
import plistlib
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Any

from veritas.timeline.schema import Desc

from . import ios_db
from .common import (
    ParseResult,
    ParserError,
    dt_to_ns,
    guard,
    load_plist,
    make_event,
    open_sqlite,
    s_to_ns,
    source_name,
    text,
)
from veritas.cloud.base import apply_provenance, provenance_fields, redact_last4

SOURCE_SHORT = "IOS"
FILE_FLAGS = {1: "file", 2: "directory", 4: "symlink"}
PII_KEYS = ("IMEI", "MEID", "Phone Number", "Serial Number", "ICCID", "Unique Identifier", "Target Identifier")


def file_id(domain: str, relative_path: str) -> str:
    return hashlib.sha1(f"{domain}-{relative_path}".encode("utf-8")).hexdigest()


@dataclass(slots=True)
class ManifestEntry:
    file_id: str
    domain: str
    relative_path: str
    flags: int
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def kind(self) -> str:
        return FILE_FLAGS.get(self.flags, str(self.flags))


def decode_file_blob(blob: Any) -> dict[str, Any]:
    """Decode the NSKeyedArchiver ``MBFile`` plist stored in ``Files.file``."""
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return {}
    try:
        archive = plistlib.loads(bytes(blob))
    except Exception:  # noqa: BLE001 - any decode failure just means "no metadata"
        return {}
    if not isinstance(archive, dict):
        return {}
    objects = archive.get("$objects")
    top = archive.get("$top")
    if not isinstance(objects, list) or not isinstance(top, dict):
        return {k: v for k, v in archive.items() if isinstance(k, str)}
    root = top.get("root")

    def resolve(v: Any) -> Any:
        if isinstance(v, plistlib.UID):
            idx = v.data
            if 0 <= idx < len(objects):
                obj = objects[idx]
                return None if obj == "$null" else obj
            return None
        return v

    rootobj = resolve(root)
    if not isinstance(rootobj, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in rootobj.items():
        if key == "$class":
            continue
        value = resolve(value)
        if isinstance(value, (str, int, float, bool, bytes)) or value is None:
            out[key] = value
    return out


def _host_from(info: dict) -> str | None:
    return text(info.get("Device Name")) if isinstance(info, dict) else None


class IosBackup:
    """Read-only view of a backup directory."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = os.fspath(root)
        if not os.path.isdir(self.root):
            raise ParserError(f"not a backup directory: {source_name(root)}")
        self.manifest_plist = self._plist("Manifest.plist")
        if self.manifest_plist.get("IsEncrypted"):
            raise ParserError(
                "encrypted iOS backup (Manifest.plist IsEncrypted=true): decryption of encrypted backups is out of "
                "scope; create an unencrypted backup or decrypt it with the examiner's own tooling first"
            )
        self.info = self._plist("Info.plist")
        self.status = self._plist("Status.plist")
        db_path = os.path.join(self.root, "Manifest.db")
        if not os.path.isfile(db_path):
            if os.path.isfile(os.path.join(self.root, "Manifest.mbdb")):
                raise ParserError("legacy Manifest.mbdb backup (iOS 9 and earlier) is not supported")
            raise ParserError("Manifest.db missing: not an iOS 10+ backup directory")
        self.entries = self._read_manifest(db_path)
        self._by_path = {(e.domain, e.relative_path): e for e in self.entries}

    def _plist(self, name: str) -> dict:
        p = os.path.join(self.root, name)
        if not os.path.isfile(p):
            return {}
        value = load_plist(p)
        if not isinstance(value, dict):
            raise ParserError(f"{name}: root is not a dictionary")
        return value

    @staticmethod
    def _read_manifest(db_path: str) -> list[ManifestEntry]:
        conn = open_sqlite(db_path)
        try:
            if "Files" not in {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}:
                raise ParserError("Manifest.db has no Files table")
            entries = []
            for row in conn.execute("SELECT fileID, domain, relativePath, flags, file FROM Files ORDER BY domain, relativePath, fileID"):
                entries.append(ManifestEntry(
                    file_id=text(row["fileID"]) or "", domain=text(row["domain"]) or "",
                    relative_path=text(row["relativePath"]) or "", flags=row["flags"] if isinstance(row["flags"], int) else 0,
                    metadata=decode_file_blob(row["file"]),
                ))
            return entries
        finally:
            conn.close()

    def lookup(self, domain: str, relative_path: str) -> ManifestEntry | None:
        return self._by_path.get((domain, relative_path))

    def content_path(self, entry: ManifestEntry) -> str | None:
        fid = entry.file_id
        if len(fid) < 3 or any(c not in "0123456789abcdefABCDEF" for c in fid):
            return None
        for candidate in (os.path.join(self.root, fid[:2], fid), os.path.join(self.root, fid)):
            if os.path.isfile(candidate):
                return candidate
        return None

    @property
    def device_name(self) -> str | None:
        return _host_from(self.info)


def _info_event(backup: IosBackup, sha: str) -> list:
    info = backup.info
    if not info:
        return []
    attrs: dict[str, Any] = {
        "device_name": info.get("Device Name"), "display_name": info.get("Display Name"),
        "product_type": info.get("Product Type"), "product_name": info.get("Product Name"),
        "product_version": info.get("Product Version"), "build_version": info.get("Build Version"),
        "serial_number": info.get("Serial Number"), "imei": info.get("IMEI"), "meid": info.get("MEID"),
        "phone_number": info.get("Phone Number"), "iccid": info.get("ICCID"),
        "unique_identifier": info.get("Unique Identifier"), "guid": info.get("GUID"),
        "itunes_version": info.get("iTunes Version"), "target_type": info.get("Target Type"),
        "pii": sorted(k.lower().replace(" ", "_") for k in PII_KEYS if info.get(k)),
    }
    msg = (
        f"iOS backup of {info.get('Device Name') or '?'} ({info.get('Product Type') or '?'}, iOS "
        f"{info.get('Product Version') or '?'}) serial {redact_last4(info.get('Serial Number')) or '-'} "
        f"IMEI {redact_last4(info.get('IMEI')) or '-'} phone {redact_last4(info.get('Phone Number')) or '-'}"
    )
    return [make_event(
        data_type="ios:backup:info", timestamp_desc="Last Backup Time", message=msg,
        timestamp=dt_to_ns(info.get("Last Backup Date")), source_short=SOURCE_SHORT, source_long="iOS backup Info.plist",
        parser="ios_backup", evidence_path="Info.plist", evidence_sha256=sha, host=backup.device_name,
        timezone="UTC", attrs=attrs,
    )]


def _status_event(backup: IosBackup, sha: str) -> list:
    st = backup.status
    if not st:
        return []
    attrs = {k.lower(): st.get(k) for k in ("Version", "BackupState", "SnapshotState", "IsFullBackup", "UUID") if k in st}
    return [make_event(
        data_type="ios:backup:status", timestamp_desc=Desc.END,
        message=f"Backup status {st.get('SnapshotState') or '?'} full={st.get('IsFullBackup')}",
        timestamp=dt_to_ns(st.get("Date")), source_short=SOURCE_SHORT, source_long="iOS backup Status.plist",
        parser="ios_backup", evidence_path="Status.plist", evidence_sha256=sha, host=backup.device_name,
        timezone="UTC", attrs=attrs,
    )]


def _app_events(backup: IosBackup, sha: str) -> list:
    apps = backup.manifest_plist.get("Applications")
    out = []
    if not isinstance(apps, dict):
        return out
    for index, bundle_id in enumerate(sorted(apps)):
        info = apps[bundle_id] if isinstance(apps[bundle_id], dict) else {}
        attrs = {
            "bundle_id": bundle_id, "version": text(info.get("CFBundleVersion")),
            "short_version": text(info.get("CFBundleShortVersionString")), "path": text(info.get("Path")),
            "container_content_class": text(info.get("ContainerContentClass")),
        }
        out.append(make_event(
            data_type="ios:app:installed", timestamp_desc=Desc.NOT_A_TIME,
            message=f"Installed app {bundle_id} version {attrs['version'] or '?'}", timestamp=None,
            source_short=SOURCE_SHORT, source_long="iOS backup Manifest.plist", parser="ios_backup",
            evidence_path="Manifest.plist", evidence_sha256=sha, offset=index, host=backup.device_name, attrs=attrs,
        ))
    return out


def _file_events(backup: IosBackup, sha: str) -> list:
    out = []
    for index, e in enumerate(backup.entries):
        md = e.metadata
        attrs = {
            "file_id": e.file_id, "domain": e.domain, "relative_path": e.relative_path, "flags": e.flags,
            "kind": e.kind, "size": md.get("Size"), "mode": oct(md["Mode"]) if isinstance(md.get("Mode"), int) else None,
            "inode": md.get("InodeNumber"), "uid": md.get("UserID"), "gid": md.get("GroupID"),
            "protection_class": md.get("ProtectionClass"),
        }
        msg = f"{e.kind} {e.domain}/{e.relative_path} size={md.get('Size')}"
        for key, desc in (("LastModified", Desc.MODIFICATION), ("Birth", Desc.CREATION),
                          ("LastStatusChange", Desc.METADATA_MODIFICATION)):
            ts = s_to_ns(md.get(key))
            if ts is None:
                continue
            out.append(make_event(
                data_type="ios:backup:file", timestamp_desc=desc, message=msg, timestamp=ts, source_short=SOURCE_SHORT,
                source_long="iOS backup Manifest.db", parser="ios_backup", evidence_path=f"{e.domain}/{e.relative_path}",
                evidence_sha256=sha, offset=index, host=backup.device_name, timezone="UTC", attrs=attrs,
            ))
    return out


def parse_backup(root: str | os.PathLike[str], *, evidence_sha256: str = "", file_events: bool = True) -> ParseResult:
    result = ParseResult()
    with guard("iOS backup"):
        backup = IosBackup(root)
        result.events.extend(_info_event(backup, evidence_sha256))
        result.events.extend(_status_event(backup, evidence_sha256))
        result.events.extend(_app_events(backup, evidence_sha256))
        if file_events:
            result.events.extend(_file_events(backup, evidence_sha256))
        for e in backup.entries:
            if e.flags not in (1, 0):
                continue
            fn = ios_db.parser_for(e.relative_path)
            if fn is None:
                continue
            content = backup.content_path(e)
            label = f"{e.domain}/{e.relative_path}"
            if content is None:
                result.warn(f"{label}: content file {e.file_id} missing from backup")
                continue
            try:
                sub = fn(content, evidence_path=label, evidence_sha256=evidence_sha256)
            except ParserError as exc:
                result.warn(f"{label}: {exc}")
                continue
            for ev in sub.events:
                if ev.host is None:
                    ev.host = backup.device_name
            result.extend(sub)
    return result


MAX_ARCHIVE_BYTES = 16 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 2_000_000


def _safe_member(name: str) -> str | None:
    norm = name.replace("\\", "/")
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    if not parts or norm.startswith("/") or ".." in parts or ":" in parts[0]:
        return None
    return "/".join(parts)


def _extract_archive(archive: str, dest: str) -> None:
    """Extract a zip/tar of a backup directory, refusing traversal, links and oversized content."""
    total = 0
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise ParserError("archive has too many members")
            for info in infos:
                rel = _safe_member(info.filename)
                if rel is None or info.is_dir():
                    continue
                total += info.file_size
                if total > MAX_ARCHIVE_BYTES:
                    raise ParserError("archive expands beyond the size limit")
                target = os.path.join(dest, *rel.split("/"))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
        return
    try:
        tf = tarfile.open(archive, mode="r:*")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ParserError(f"not a backup directory, zip or tar archive: {exc}") from exc
    with tf:
        count = 0
        for member in tf:
            count += 1
            if count > MAX_ARCHIVE_MEMBERS:
                raise ParserError("archive has too many members")
            rel = _safe_member(member.name)
            if rel is None or not member.isfile():
                continue
            total += member.size
            if total > MAX_ARCHIVE_BYTES:
                raise ParserError("archive expands beyond the size limit")
            target = os.path.join(dest, *rel.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)


def _find_root(base: str) -> str:
    """Shallowest directory holding Manifest.db or Manifest.plist."""
    best: tuple[int, str] | None = None
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        if "Manifest.db" in filenames or "Manifest.plist" in filenames or "Manifest.mbdb" in filenames:
            depth = os.path.relpath(dirpath, base).count(os.sep)
            if best is None or depth < best[0]:
                best = (depth, dirpath)
    if best is None:
        raise ParserError("archive does not contain an iOS backup (no Manifest.db / Manifest.plist)")
    return best[1]


def parse(source, provenance=None, *, evidence_sha256: str = "", file_events: bool = True) -> ParseResult:
    """Pipeline entry point: ``source`` is a backup directory or a zip/tar of one.

    ``provenance`` is a ``veritas.parsers.base.Provenance`` (or any object exposing
    ``evidence_sha256`` / ``evidence_path``). Iterating the returned result yields Events.
    """
    _, evidence_sha256 = provenance_fields(provenance, "", evidence_sha256)
    if not isinstance(source, (str, os.PathLike)):
        raise ParserError("iOS backup source must be a directory or archive path")
    if os.path.isdir(source):
        return apply_provenance(parse_backup(source, evidence_sha256=evidence_sha256, file_events=file_events), provenance)
    if not os.path.isfile(source):
        raise ParserError(f"no such backup: {source_name(source)}")
    with guard("iOS backup archive"), tempfile.TemporaryDirectory(prefix="veritas-ios-") as tmp:
        _extract_archive(os.fspath(source), tmp)
        result = parse_backup(_find_root(tmp), evidence_sha256=evidence_sha256, file_events=file_events)
    return apply_provenance(result, provenance)
