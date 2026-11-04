"""Google Santa (macOS binary authorization) ``santa.log``.

``[ISO8601] <L> santad: action=<A>|key=value|...``. Data types follow plaso:
EXEC -> ``santa:execution`` (Last Time Executed); WRITE/RENAME/DELETE/LINK ->
``santa:file_system_event`` (Content Modification Time); DISKAPPEAR/DISKDISAPPEAR ->
``santa:diskmount`` (Content Modification Time, plus First Connection Time from ``appearance``);
EXIT -> ``santa:process_exit`` (Exit Time). Other lines (quota notices) are skipped. Newer
santa releases prefix ``santad:`` with the process tag in different ways; any
``action=...`` key/value payload is accepted.
"""
from __future__ import annotations

import re
from typing import Iterator

from veritas.parsers.text_log import TextLogParser
from veritas.timeline.schema import Desc, Event, iso_to_ns

LINE = re.compile(r"^\[(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\]\s+(?P<lvl>[A-Z])\s+\S+?:\s+(?P<kv>action=.*)$")
TYPES = {"EXEC": ("santa:execution", Desc.LAST_RUN), "WRITE": ("santa:file_system_event", Desc.MODIFICATION),
         "RENAME": ("santa:file_system_event", Desc.MODIFICATION), "DELETE": ("santa:file_system_event", Desc.MODIFICATION),
         "LINK": ("santa:file_system_event", Desc.MODIFICATION), "EXCHANGE": ("santa:file_system_event", Desc.MODIFICATION),
         "DISKAPPEAR": ("santa:diskmount", Desc.MODIFICATION), "DISKDISAPPEAR": ("santa:diskmount", Desc.MODIFICATION),
         "EXIT": ("santa:process_exit", "Exit Time"), "FORK": ("santa:process_exit", "Fork Time")}
INTS = {"pid", "ppid", "uid", "gid", "pidversion"}


def _kv(text: str) -> dict:
    out = {}
    for part in text.split("|"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = None if v in ("", "(null)") else (int(v) if k in INTS and v.lstrip("-").isdigit() else v)
    return out


class SantaParser(TextLogParser):
    name = "santa"
    version = "1.0"
    source_short = "LOG"
    source_long = "Santa"
    head_regex = re.compile(r"^\[\d{4}-\d{2}-\d{2}T[\d:.]+Z\] [A-Z] santad:", re.M)

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        m = LINE.match(line)
        if not m:
            return
        kv = _kv(m.group("kv"))
        action = kv.get("action") or ""
        dtype, desc = TYPES.get(action, ("santa:event", Desc.EVENT))
        ts = iso_to_ns(m.group("ts"))
        if action == "EXEC":
            msg = f"{kv.get('decision')} process: {kv.get('path')} hash: {kv.get('sha256')}"
        elif dtype == "santa:diskmount":
            msg = f"Santa {action} on ({kv.get('mount')}) serial: ({kv.get('serial')}) for ({kv.get('bsdname')})"
        else:
            msg = f"Santa {action} event {kv.get('path')} by process: {kv.get('process')}"
        attrs = {k: v for k, v in kv.items()}
        attrs["log_level"] = m.group("lvl")
        yield self.event(dtype, desc, msg, ts, offset=lineno, attrs=attrs, user=kv.get("user"))
        if dtype == "santa:diskmount" and kv.get("appearance"):
            app = iso_to_ns(kv["appearance"])
            if app is not None and not kv["appearance"].startswith("2001-01-01T00:00:00"):
                yield self.event(dtype, "First Connection Time", msg, app, offset=lineno, attrs=attrs)


PARSERS = [SantaParser]
