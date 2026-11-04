"""Windows Recycle Bin metadata.

* ``$I`` files (Vista+). Version 1 (Vista-8.1): version(8) size(8) deletion FILETIME(8)
  path UTF-16 (520 bytes fixed). Version 2 (Windows 10+): version(8) size(8) FILETIME(8)
  name length in characters(4) path UTF-16 (length-prefixed).
* ``INFO2`` (Windows 95-XP): 20-byte header with the record size at offset 12 (280 on 9x,
  800 on NT); each record: ANSI path(260) index(4) drive(4) FILETIME(8) size(4)
  [UTF-16 path(520) on NT].

All produce ``windows:metadata:deleted_item`` with ``Content Deletion Time``.
"""
from __future__ import annotations

import os
import pathlib
import struct
from typing import Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.timeline.schema import Event, filetime_to_ns

DELETED = "Content Deletion Time"
MAX_INFO2 = 64 * 1024 * 1024


def _utf16z(buf: bytes) -> str:
    for i in range(0, len(buf) - 1, 2):
        if buf[i] == 0 and buf[i + 1] == 0:
            buf = buf[:i]
            break
    return buf.decode("utf-16-le", "replace")


class RecycleBinIParser(BaseParser):
    name = "recycle_bin"
    version = "1.0"
    source_short = "RECBIN"
    source_long = "Recycle Bin"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        base = pathlib.Path(path).name
        return base.upper().startswith("$I") and len(head_bytes) >= 24 and head_bytes[:8] in (
            b"\x01" + b"\x00" * 7, b"\x02" + b"\x00" * 7)

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open(path, "rb") as fh:
            data = fh.read(8 + 8 + 8 + 4 + 2 * 32768 + 2)
        if len(data) < 24:
            raise ParserError("recycle_bin: $I file shorter than 24 bytes")
        version, size, ft = struct.unpack_from("<QQQ", data, 0)
        if version == 1:
            name = _utf16z(data[24:24 + 520])
        elif version == 2:
            if len(data) < 28:
                raise ParserError("recycle_bin: truncated v2 header")
            nchars = struct.unpack_from("<I", data, 24)[0]
            if nchars > 32768:
                raise ParserError(f"recycle_bin: implausible name length {nchars}")
            name = _utf16z(data[28:28 + 2 * nchars])
        else:
            raise ParserError(f"recycle_bin: unsupported $I version {version}")
        attrs = {"original_filename": name, "file_size": size, "format_version": version,
                 "recycle_bin_filename": pathlib.Path(path).name}
        yield self.event("windows:metadata:deleted_item", DELETED, f"DC0 -> {name} (from drive: {name[:2]})",
                         filetime_to_ns(ft), offset=0, attrs=attrs)


class RecyclerInfo2Parser(BaseParser):
    name = "recycle_bin_info2"
    version = "1.0"
    source_short = "RECBIN"
    source_long = "Recycle Bin INFO2"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        if pathlib.Path(path).name.upper() != "INFO2" or len(head_bytes) < 20:
            return False
        return struct.unpack_from("<I", head_bytes, 12)[0] in (280, 800)

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        if os.path.getsize(path) > MAX_INFO2:
            raise ParserError("recycle_bin_info2: file too large")
        data = pathlib.Path(path).read_bytes()
        if len(data) < 20:
            raise ParserError("recycle_bin_info2: header truncated")
        rec_size = struct.unpack_from("<I", data, 12)[0]
        if rec_size not in (280, 800):
            raise ParserError(f"recycle_bin_info2: unsupported record size {rec_size}")
        off = 20
        while off + 280 <= len(data):
            try:
                rec = data[off:off + rec_size]
                if len(rec) < 280:
                    self.warn(f"truncated record at {off}")
                    break
                ansi = rec[:260].split(b"\x00", 1)[0].decode("latin-1")
                index, drive, ft, size = struct.unpack_from("<IIQI", rec, 260)
                uni = _utf16z(rec[280:800]) if rec_size == 800 and len(rec) >= 800 else ""
                name = uni or ansi
                attrs = {"original_filename": name, "record_index": index, "drive_number": drive,
                         "file_size": size, "ansi_filename": ansi}
                drive_letter = chr(ord("A") + drive) if drive < 26 else "?"
                yield self.event("windows:metadata:deleted_item", DELETED,
                                 f"DC{index} -> {name} (from drive: {drive_letter})",
                                 filetime_to_ns(ft) if ft else None, offset=off, attrs=attrs)
            except Exception as exc:  # noqa: BLE001
                self.warn(f"record at {off}: {exc}")
            off += rec_size


PARSERS = [RecycleBinIParser, RecyclerInfo2Parser]
