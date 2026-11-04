"""macOS launchd log (``/private/var/log/com.apple.xpc.launchd/launchd.log*``).

``YYYY-MM-DD HH:MM:SS.ffffff [(subsystem)] <Level>: message``. Timestamps are local time as
written (``attrs.time_is_local``). Lines that do not start with a timestamp are continuations of
the previous message. -> ``macos:launchd_log:entry`` (Content Modification Time).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import TextLogParser
from veritas.timeline.schema import NS, Desc, Event

LINE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d{1,9}))?\s+(?:\((?P<sub>[^)]*)\)\s+)?"
                  r"<(?P<level>\w+)>:\s?(?P<msg>.*)$")


class LaunchdLogParser(TextLogParser):
    name = "macos_launchd_log"
    version = "1.0"
    source_short = "LOG"
    source_long = "launchd log"
    head_regex = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ (\([^)]*\) )?<(Notice|Error|Warning|Debug|Info|Critical)>:", re.M)

    def begin(self, prov: Provenance) -> None:
        self.cur: dict[str, Any] | None = None

    def _flush(self) -> Iterator[Event]:
        if self.cur is None:
            return
        c, self.cur = self.cur, None
        attrs = {"subsystem": c["sub"], "severity": c["level"], "body": c["msg"], "time_is_local": True}
        msg = f"{'(' + c['sub'] + ') ' if c['sub'] else ''}<{c['level']}>: {c['msg']}"
        yield self.event("macos:launchd_log:entry", Desc.MODIFICATION, msg, c["ts"], offset=c["lineno"], attrs=attrs)

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        m = LINE.match(line)
        if not m:
            if self.cur is not None and len(self.cur["msg"]) < 65536:
                self.cur["msg"] += "\n" + line
            elif line.strip():
                self.warn(f"line {lineno}: not a launchd log line")
            return
        yield from self._flush()
        try:
            dt = datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            frac = m.group("frac")
            ts = int(dt.timestamp()) * NS + (int((frac + "000000000")[:9]) if frac else 0)
        except ValueError:
            ts = None
        self.cur = {"ts": ts, "sub": m.group("sub"), "level": m.group("level"), "msg": m.group("msg"), "lineno": lineno}

    def finish(self) -> Iterator[Event]:
        yield from self._flush()


PARSERS = [LaunchdLogParser]
