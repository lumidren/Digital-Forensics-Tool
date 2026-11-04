"""Login accounting records.

* Linux ``utmp``/``wtmp``/``btmp`` (glibc ``struct utmp``, 384 bytes, little-endian):
  type i32 | pid i32 | line[32] | id[4] | user[32] | host[256] | exit(term i16, exit i16) |
  session i32 | tv_sec i32 | tv_usec i32 | addr_v6 4*u32 | unused[20]
  -> ``linux:utmp:event``.
* macOS ``utmpx`` (628 bytes): user[256] | id[4] | line[32] | pid i32 | type i16 | pad i16 |
  tv_sec i32 | tv_usec i32 | host[256] | pad[64] -> ``macos:utmpx:entry``.

Corrupt input yields partial results: a record whose type is out of range or whose strings are
not text is skipped with a warning; a trailing partial record is reported and ignored. Empty
records (type 0 and all-zero) are skipped silently.
"""
from __future__ import annotations

import ipaddress
import os
import pathlib
import struct
from typing import Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.timeline.schema import NS, Desc, Event

LINUX_SIZE = 384
MAC_SIZE = 628
TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME", 5: "INIT_PROCESS",
         6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS", 9: "ACCOUNTING", 10: "SIGNATURE", 11: "SHUTDOWN_TIME"}
MAX_FILE = 256 * 1024 * 1024
LINUX_NAMES = ("utmp", "wtmp", "btmp")


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _printable(s: str) -> bool:
    return all(ch.isprintable() for ch in s)


def _linux_record_ok(rec: bytes) -> bool:
    typ = struct.unpack_from("<i", rec, 0)[0]
    return 0 <= typ <= 9 and _printable(_cstr(rec[8:40])) and _printable(_cstr(rec[44:76]))


class UtmpParser(BaseParser):
    name = "utmp"
    version = "1.0"
    source_short = "LOG"
    source_long = "Linux utmp/wtmp/btmp"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        n = pathlib.Path(path).name.lower()
        if not any(n.startswith(x) for x in LINUX_NAMES) or len(head_bytes) < LINUX_SIZE:
            return False
        return _linux_record_ok(head_bytes[:LINUX_SIZE])

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        size = os.path.getsize(path)
        if size > MAX_FILE:
            raise ParserError("utmp: file too large")
        if size < LINUX_SIZE:
            raise ParserError("utmp: file shorter than one record")
        with open(path, "rb") as fh:
            index = 0
            while True:
                rec = fh.read(LINUX_SIZE)
                if not rec:
                    break
                off = index * LINUX_SIZE
                index += 1
                if len(rec) < LINUX_SIZE:
                    self.warn(f"trailing partial record at {off} ({len(rec)} bytes)")
                    break
                try:
                    if not any(rec):
                        continue
                    if not _linux_record_ok(rec):
                        self.warn(f"record {index - 1} at {off}: invalid type or non-text fields")
                        continue
                    (typ, pid) = struct.unpack_from("<ii", rec, 0)
                    line, rid, user, host = _cstr(rec[8:40]), _cstr(rec[40:44]), _cstr(rec[44:76]), _cstr(rec[76:332])
                    term, exitc, session, sec, usec = struct.unpack_from("<hhiii", rec, 332)
                    addr_raw = rec[348:364]
                    if any(addr_raw[4:]):
                        ip = str(ipaddress.IPv6Address(addr_raw))
                    elif any(addr_raw[:4]):
                        ip = str(ipaddress.IPv4Address(addr_raw[:4]))
                    else:
                        ip = None
                    attrs = {"type": typ, "type_name": TYPES.get(typ), "pid": pid, "terminal": line,
                             "terminal_identifier": rid, "username": user, "hostname": host, "ip_address": ip,
                             "exit_status": exitc, "termination_status": term, "session": session}
                    ts = sec * NS + usec * 1000 if sec >= 0 and 0 <= usec < 1_000_000 and (sec or usec) else None
                    msg = f"User: {user or 'N/A'} Hostname: {host or 'N/A'} Terminal: {line or 'N/A'} PID: {pid} Type: {TYPES.get(typ, typ)}"
                    yield self.event("linux:utmp:event", Desc.MODIFICATION, msg, ts, offset=off, attrs=attrs,
                                     user=user or None)
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"record at {off}: {exc}")


class UtmpxMacParser(BaseParser):
    name = "utmpx_macos"
    version = "1.0"
    source_short = "LOG"
    source_long = "macOS utmpx"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return head_bytes.startswith(b"utmpx-1.00")

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        size = os.path.getsize(path)
        if size > MAX_FILE:
            raise ParserError("utmpx: file too large")
        with open(path, "rb") as fh:
            first = fh.read(MAC_SIZE)
            if not first.startswith(b"utmpx-1.00"):
                raise ParserError("utmpx: missing utmpx-1.00 signature record")
            index = 1
            while True:
                rec = fh.read(MAC_SIZE)
                if not rec:
                    break
                off = index * MAC_SIZE
                index += 1
                if len(rec) < MAC_SIZE:
                    self.warn(f"trailing partial record at {off}")
                    break
                try:
                    user, rid, line = _cstr(rec[0:256]), rec[256:260], _cstr(rec[260:292])
                    pid, typ = struct.unpack_from("<ih", rec, 292)
                    sec, usec = struct.unpack_from("<ii", rec, 300)
                    host = _cstr(rec[308:564])
                    if typ not in TYPES:
                        self.warn(f"record at {off}: invalid type {typ}")
                        continue
                    attrs = {"type": typ, "type_name": TYPES.get(typ), "pid": pid, "terminal": line,
                             "terminal_identifier": int.from_bytes(rid, "little"), "username": user, "hostname": host}
                    ts = sec * NS + usec * 1000 if sec >= 0 and 0 <= usec < 1_000_000 and (sec or usec) else None
                    msg = f"User: {user or 'N/A'} Hostname: {host or 'N/A'} Terminal: {line or 'N/A'} PID: {pid} Type: {TYPES.get(typ)}"
                    yield self.event("macos:utmpx:entry", Desc.MODIFICATION, msg, ts, offset=off, attrs=attrs,
                                     user=user or None)
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"record at {off}: {exc}")


PARSERS = [UtmpParser, UtmpxMacParser]
