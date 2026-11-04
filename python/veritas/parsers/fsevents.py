"""macOS FSEvents (``/.fseventsd/<hex>``): gzip-compressed DLS pages.

The decompressed stream is a sequence of pages; each page starts with a 12-byte header:
magic (``1SLD`` = DLS1, ``2SLD`` = DLS2, ``3SLD`` = DLS3), unknown u32, page size u32 (header
included). Records follow until the page end:

* DLS1: path (NUL-terminated UTF-8) | event_id u64 | flags u32
* DLS2: path | event_id u64 | flags u32 | node_id u64
* DLS3: path | event_id u64 | flags u32 | node_id u64 | unknown u32

FSEvents records carry no timestamp. As in plaso, the event time is the modification time of the
fseventsd file itself, supplied by the caller as ``Provenance.mtime_ns``; without it events are
``Not a time``. Decompression is capped at 256 MiB (decompression-bomb guard, THREAT T3.5).
-> ``macos:fseventsd:record`` with ``attrs.flags`` (int) and ``attrs.flag_names``.
"""
from __future__ import annotations

import gzip
import struct
import zlib
from typing import Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.timeline.schema import Event

MAGICS = {b"1SLD": 1, b"2SLD": 2, b"3SLD": 3}
MAX_DECOMPRESSED = 256 * 1024 * 1024
FLAG_NAMES = [
    (0x00000001, "Created"), (0x00000002, "Removed"), (0x00000004, "InodeMetadataModified"), (0x00000008, "Renamed"),
    (0x00000010, "Modified"), (0x00000020, "Exchange"), (0x00000040, "FinderInfoModified"), (0x00000080, "DirectoryCreated"),
    (0x00000100, "PermissionChanged"), (0x00000200, "ExtendedAttributeModified"), (0x00000400, "ExtendedAttributeRemoved"),
    (0x00000800, "DocumentCreated"), (0x00001000, "DocumentRevision"), (0x00002000, "UnmountPending"),
    (0x00004000, "ItemCloned"), (0x00010000, "NotificationClone"), (0x00020000, "ItemTruncated"),
    (0x00040000, "DirectoryEvent"), (0x00080000, "LastHardLinkRemoved"), (0x00100000, "IsHardLink"),
    (0x00400000, "IsSymbolicLink"), (0x00800000, "IsFile"), (0x01000000, "IsDirectory"), (0x02000000, "Mount"),
    (0x04000000, "Unmount"), (0x20000000, "EndOfTransaction"),
]
FILE_MODIFIED = "File Last Modification Time"


def flag_names(flags: int) -> list[str]:
    return [name for bit, name in FLAG_NAMES if flags & bit]


def decompress(path: str, cap: int = MAX_DECOMPRESSED) -> bytes:
    with open(path, "rb") as fh:
        raw_head = fh.read(2)
    if raw_head != b"\x1f\x8b":
        with open(path, "rb") as fh:
            data = fh.read(cap + 1)  # already-decompressed page dump
    else:
        out = bytearray()
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                try:
                    out += d.decompress(chunk, cap + 1 - len(out))
                except zlib.error as exc:
                    if out:
                        break  # truncated/corrupt tail: keep what we have
                    raise ParserError(f"fsevents: gzip error: {exc}") from exc
                if len(out) > cap:
                    raise ParserError("fsevents: decompressed size exceeds cap")
        data = bytes(out)
    if len(data) > cap:
        raise ParserError("fsevents: decompressed size exceeds cap")
    return data


class FseventsParser(BaseParser):
    name = "fseventsd"
    version = "1.0"
    source_short = "FILE"
    source_long = "FSEvents"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        if head_bytes[:4] in MAGICS:
            return True
        if head_bytes[:2] != b"\x1f\x8b":
            return False
        try:
            return gzip.decompress(head_bytes[:4096])[:4] in MAGICS  # may fail on partial stream
        except Exception:  # noqa: BLE001
            try:
                return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(head_bytes, 16)[:4] in MAGICS
            except zlib.error:
                return False

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        data = decompress(path)
        if data[:4] not in MAGICS:
            raise ParserError("fsevents: no DLS page signature")
        ts = prov.mtime_ns
        pos = 0
        page = 0
        while pos + 12 <= len(data):
            magic = data[pos:pos + 4]
            if magic not in MAGICS:
                self.warn(f"page {page} at {pos}: bad signature {magic!r}")
                break
            version = MAGICS[magic]
            size = struct.unpack_from("<I", data, pos + 8)[0]
            end = pos + size
            if size < 12 or end > len(data):
                self.warn(f"page {page} at {pos}: size {size} out of range; truncated")
                end = len(data)
            rec = pos + 12
            tail = {1: 12, 2: 20, 3: 24}[version]
            while rec < end:
                nul = data.find(b"\x00", rec, end)
                if nul < 0 or nul + 1 + tail > end:
                    if rec < end:
                        self.warn(f"page {page}: truncated record at {rec}")
                    break
                path_s = data[rec:nul].decode("utf-8", "replace")
                event_id, flags = struct.unpack_from("<QI", data, nul + 1)
                node_id = struct.unpack_from("<Q", data, nul + 13)[0] if version >= 2 else None
                attrs = {"path": path_s, "event_identifier": event_id, "flags": flags, "flag_names": flag_names(flags),
                         "node_identifier": node_id, "format_version": version, "page": page}
                msg = f"{path_s} {','.join(attrs['flag_names'])} event_identifier: {event_id}"
                yield self.event("macos:fseventsd:record", FILE_MODIFIED, msg, ts, offset=rec, attrs=attrs)
                rec = nul + 1 + tail
            pos = end
            page += 1


PARSERS = [FseventsParser]
