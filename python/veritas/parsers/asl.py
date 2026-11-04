"""Apple System Log binary store (``/var/log/asl/*.asl``, "ASL DB" format version 2).

Big-endian. File header: signature ``ASL DB\\0\\0\\0\\0\\0\\0`` (12) | version u32 | first record
offset u64 | creation time u64 | cache size u32 | last record offset u64 | 36 reserved.

Record (98 fixed bytes): unknown u16 | data_size u32 | next_record_offset u64 | message id u64 |
written_time u64 (s) | nanoseconds u32 | level u16 | flags u16 | pid u32 | uid i32 | gid i32 |
read uid i32 | read gid i32 | ref pid u64 | hostname, sender, facility, message string offsets u64;
then ``(data_size + 6 - 98 - 8) / 16`` extra key/value string-offset pairs and an 8-byte
previous-record offset. A string offset with the MSB set holds up to 7 bytes inline (size in
bits 56-59); otherwise it points to ``u16 | u32 size | bytes``.

Records are followed through ``next_record_offset`` with a visited set (loops are reported and
stop the walk). -> ``macos:asl:entry`` (Content Modification Time) and one ``macos:asl:file``
event for the header creation time.
"""
from __future__ import annotations

import os
import struct
from typing import Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance, clip
from veritas.timeline.schema import NS, Desc, Event

SIGNATURE = b"ASL DB\x00\x00\x00\x00\x00\x00"
HEADER = struct.Struct(">12sIQQIQ36s")
RECORD = struct.Struct(">HIQQQIHHIiiiiQQQQQ")
LEVELS = {0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR", 4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"}
MAX_FILE = 512 * 1024 * 1024
MAX_STRING = 65536


class AslParser(BaseParser):
    name = "asl_log"
    version = "1.0"
    source_short = "LOG"
    source_long = "ASL"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return head_bytes.startswith(SIGNATURE)

    def _string(self, fh, size: int, off: int) -> str | None:
        if off == 0:
            return None
        if off & (1 << 63):
            if off >> 60 != 8:
                raise ValueError("invalid inline string flag")
            n = (off >> 56) & 0x0F
            if n >= 8:
                raise ValueError("invalid inline string size")
            raw = bytes((off >> (8 * i)) & 0xFF for i in range(6, -1, -1))[:n]
            return raw.decode("utf-8", "replace")
        if off + 6 > size:
            raise ValueError(f"string offset {off} out of range")
        fh.seek(off)
        hdr = fh.read(6)
        _, n = struct.unpack(">HI", hdr)
        data = fh.read(min(n, MAX_STRING))
        return clip(data.split(b"\x00", 1)[0].decode("utf-8", "replace"))

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        size = os.path.getsize(path)
        if size > MAX_FILE:
            raise ParserError("asl: file too large")
        with open(path, "rb") as fh:
            raw = fh.read(HEADER.size)
            if len(raw) < HEADER.size or not raw.startswith(SIGNATURE):
                raise ParserError("asl: bad signature or truncated header")
            _, fmt_version, first, created, _cache, _last, _ = HEADER.unpack(raw)
            if fmt_version != 2:
                raise ParserError(f"asl: unsupported format version {fmt_version}")
            yield self.event("macos:asl:file", Desc.CREATION, f"ASL file created (format {fmt_version})",
                             created * NS if created else None, offset=0, attrs={"format_version": fmt_version})
            seen: set[int] = set()
            off = first
            while 0 < off < size:
                if off in seen:
                    self.warn(f"record loop at {off:#x}")
                    break
                seen.add(off)
                try:
                    fh.seek(off)
                    raw = fh.read(RECORD.size)
                    if len(raw) < RECORD.size:
                        self.warn(f"truncated record at {off:#x}")
                        break
                    (_, data_size, nxt, msg_id, sec, nsec, level, flags, pid, uid, gid, ruid, rgid, refpid,
                     host_o, sender_o, fac_o, msg_o) = RECORD.unpack(raw)
                    extra_size = data_size + 6 - RECORD.size
                    if extra_size < 0 or extra_size % 8 or off + RECORD.size + extra_size > size:
                        self.warn(f"record at {off:#x}: bad data size {data_size}")
                        break
                    extra = fh.read(extra_size)
                    pairs = []
                    for i in range(0, max(0, extra_size - 8), 16):
                        pairs.append(struct.unpack_from(">QQ", extra, i))
                    extras = {}
                    for k_o, v_o in pairs[:256]:
                        try:
                            k = self._string(fh, size, k_o)
                            if k:
                                extras[k] = self._string(fh, size, v_o)
                        except ValueError as exc:
                            self.warn(f"record at {off:#x}: extra field: {exc}")
                    attrs = {
                        "message_identifier": msg_id, "level": LEVELS.get(level, str(level)), "flags": flags,
                        "pid": pid, "user_identifier": uid, "group_identifier": gid, "read_uid": ruid, "read_gid": rgid,
                        "reference_pid": refpid, "computer_name": self._string(fh, size, host_o),
                        "sender": self._string(fh, size, sender_o), "facility": self._string(fh, size, fac_o),
                        "message": self._string(fh, size, msg_o), "extra_information": extras,
                    }
                    ts = sec * NS + (nsec if nsec < NS else 0)
                    text = f"MessageID: {msg_id} Level: {attrs['level']} ({level}) User ID: {uid} Group ID: {gid} " \
                           f"Read User: {ruid} Read Group: {rgid} Host: {attrs['computer_name']} Sender: {attrs['sender']} " \
                           f"Facility: {attrs['facility']} Message: {attrs['message']}"
                    yield self.event("macos:asl:entry", Desc.MODIFICATION, text, ts, offset=off, attrs=attrs,
                                     host=attrs["computer_name"])
                    off = nxt
                except (ValueError, struct.error) as exc:
                    self.warn(f"record at {off:#x}: {exc}")
                    break


PARSERS = [AslParser]
