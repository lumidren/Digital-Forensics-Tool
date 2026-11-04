"""macOS Unified Logging.

Scope decision (documented limitation): the binary ``tracev3`` / ``.logarchive`` format
(chunked, LZ4-compressed, with format strings resolved through ``uuidtext`` and the shared
cache ``dsc`` files) is **not** parsed in pure Python here. Instead:

(a) :class:`UnifiedLogJsonParser` parses the exports produced on a Mac by
    ``log show --style ndjson`` (one JSON object per line) and ``log show --style json``
    (a single JSON array, decoded incrementally so large exports stream). Fields used:
    ``timestamp`` (``YYYY-MM-DD HH:MM:SS.ffffff+zzzz``), ``eventMessage``, ``processImagePath``,
    ``senderImagePath``, ``subsystem``, ``category``, ``messageType``, ``eventType``,
    ``processID``, ``threadID``, ``traceID``, ``userID``, ``bootUUID``.
    -> ``macos:unified_logging:event`` (Recorded Time).

(b) :class:`LogArchiveParser` recognises ``.logarchive`` bundles and raw ``*.tracev3`` files.
    On macOS (``sys.platform == 'darwin'``) with ``/usr/bin/log`` present it runs
    ``log show --archive <path> --style ndjson`` (argument vector, no shell, no network) and
    streams that output through (a). On every other platform it raises ``ParserError`` with an
    explanation so the pipeline records the artifact as unsupported rather than silently empty.
    For tracev3 files the containing ``.logarchive`` (or a copy of ``/private/var/db/diagnostics``
    + ``uuidtext``) must be supplied, as ``log`` needs the uuidtext/dsc companions.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance, clip
from veritas.parsers.text_log import open_binary
from veritas.timeline.schema import NS, Event

RECORDED = "Recorded Time"
TS = re.compile(r"^(?P<d>\d{4}-\d{2}-\d{2})[ T](?P<t>\d{2}:\d{2}:\d{2})(?:\.(?P<f>\d{1,9}))?(?P<tz>[+-]\d{2}:?\d{2}|Z)?$")
TRACEV3_MAGIC = b"\x00\x10\x00\x00"
MAX_OBJECT = 4 * 1024 * 1024


def parse_log_timestamp(text: str) -> int | None:
    from datetime import datetime, timedelta, timezone

    m = TS.match(text.strip()) if isinstance(text, str) else None
    if not m:
        return None
    try:
        dt = datetime.strptime(f"{m.group('d')} {m.group('t')}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    tz = m.group("tz")
    if tz and tz != "Z":
        tz = tz.replace(":", "")
        sign = 1 if tz[0] == "+" else -1
        dt -= sign * timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5]))
    frac = m.group("f")
    return int(dt.timestamp()) * NS + (int((frac + "000000000")[:9]) if frac else 0)


class UnifiedLogJsonParser(BaseParser):
    name = "macos_unified_log_json"
    version = "1.0"
    source_short = "LOG"
    source_long = "macOS Unified Log (log show export)"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        h = head_bytes.lstrip()
        return (h.startswith(b"{") or h.startswith(b"[")) and b'"eventMessage"' in head_bytes and b'"timestamp"' in head_bytes

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_binary(path) as fh:
            first = b""
            while True:
                ch = fh.read(1)
                if not ch:
                    raise ParserError("unified_log: empty file")
                if not ch.isspace():
                    first = ch
                    break
        if first == b"[":
            yield from self._array(path)
        elif first == b"{":
            yield from self._ndjson(path)
        else:
            raise ParserError("unified_log: not JSON")

    def iter_records_from_lines(self, lines: Iterator[tuple[int, str]]) -> Iterator[Event]:
        for lineno, line in lines:
            s = line.strip()
            if not s:
                continue
            if len(s) > MAX_OBJECT:
                self.warn(f"line {lineno}: object too large")
                continue
            try:
                obj = json.loads(s)
            except ValueError as exc:
                self.warn(f"line {lineno}: invalid JSON: {exc}")
                continue
            if isinstance(obj, dict):
                if "finished" in obj and len(obj) == 1:
                    continue  # ndjson trailer {"finished":1}
                yield self._event(obj, lineno)

    def _ndjson(self, path: str) -> Iterator[Event]:
        from veritas.parsers.text_log import iter_lines

        yield from self.iter_records_from_lines(iter_lines(path, warn=self.warn))

    def _array(self, path: str) -> Iterator[Event]:
        decoder = json.JSONDecoder()
        buf = ""
        index = 0
        with open_binary(path) as raw:
            import io

            fh = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
            started = False
            eof = False
            while True:
                if not eof and len(buf) < MAX_OBJECT:
                    chunk = fh.read(1024 * 1024)
                    if chunk:
                        buf += chunk
                    else:
                        eof = True
                buf = buf.lstrip()
                if not started:
                    if not buf:
                        if eof:
                            return
                        continue
                    if buf[0] != "[":
                        raise ParserError("unified_log: JSON export does not start with '['")
                    buf = buf[1:]
                    started = True
                    continue
                buf = buf.lstrip().lstrip(",").lstrip()
                if buf.startswith("]") or (eof and not buf):
                    return
                try:
                    obj, end = decoder.raw_decode(buf)
                except ValueError:
                    if eof or len(buf) >= MAX_OBJECT:
                        self.warn(f"element {index}: invalid or truncated JSON; stopping")
                        return
                    continue  # need more data
                buf = buf[end:]
                if isinstance(obj, dict):
                    yield self._event(obj, index)
                index += 1

    def _event(self, obj: dict[str, Any], offset: int) -> Event:
        ts = parse_log_timestamp(obj.get("timestamp", ""))
        attrs = {
            "event_message": clip(obj.get("eventMessage")), "process_image_path": obj.get("processImagePath"),
            "sender_image_path": obj.get("senderImagePath"), "subsystem": obj.get("subsystem"),
            "category": obj.get("category"), "message_type": obj.get("messageType"), "event_type": obj.get("eventType"),
            "process_identifier": obj.get("processID"), "thread_identifier": obj.get("threadID"),
            "activity_identifier": obj.get("activityIdentifier"), "trace_identifier": obj.get("traceID"),
            "user_identifier": obj.get("userID"), "boot_uuid": obj.get("bootUUID"),
            "format_string": clip(obj.get("formatString")), "timestamp_text": obj.get("timestamp"),
        }
        attrs = {k: (int(v) if isinstance(v, float) else v) for k, v in attrs.items()}
        proc = os.path.basename(attrs["process_image_path"] or "") or "?"
        msg = f"{proc}[{attrs['process_identifier']}] {attrs['subsystem'] or ''}:{attrs['category'] or ''} {attrs['event_message'] or ''}"
        return self.event("macos:unified_logging:event", RECORDED, msg, ts, offset=offset, attrs=attrs)


class LogArchiveParser(BaseParser):
    name = "macos_logarchive"
    version = "1.0"
    source_short = "LOG"
    source_long = "macOS Unified Log archive"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        p = path.rstrip("/\\").lower()
        return p.endswith(".logarchive") or (p.endswith(".tracev3") and head_bytes[:4] == TRACEV3_MAGIC)

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        tool = shutil.which("log") if sys.platform == "darwin" else None
        if tool is None:
            raise ParserError(
                "macos_logarchive: binary tracev3/logarchive decoding is not implemented in pure Python; "
                "export on macOS with `log show --archive <x.logarchive> --style ndjson > out.ndjson` and parse "
                "the export with macos_unified_log_json (or run this parser on macOS, where it shells out to `log`).")
        target = path
        if path.lower().endswith(".tracev3"):
            # `log show` needs the archive root; walk up to the enclosing .logarchive if any.
            parent = os.path.dirname(os.path.abspath(path))
            while parent and not parent.lower().endswith(".logarchive") and os.path.dirname(parent) != parent:
                parent = os.path.dirname(parent)
            if not parent.lower().endswith(".logarchive"):
                raise ParserError("macos_logarchive: tracev3 file is not inside a .logarchive bundle")
            target = parent
        proc = subprocess.Popen([tool, "show", "--archive", target, "--style", "ndjson", "--info", "--debug"],  # noqa: S603
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        inner = UnifiedLogJsonParser()
        inner._prov = prov  # noqa: SLF001 - share provenance for event construction
        inner.warn = self.warn  # type: ignore[method-assign]
        try:
            assert proc.stdout is not None
            lines = ((i, ln.decode("utf-8", "replace")) for i, ln in enumerate(proc.stdout, 1))
            for ev in inner.iter_records_from_lines(lines):
                ev.parser, ev.parser_version = self.name, self.version
                yield ev
        finally:
            proc.kill()
            proc.wait()


PARSERS = [UnifiedLogJsonParser, LogArchiveParser]
