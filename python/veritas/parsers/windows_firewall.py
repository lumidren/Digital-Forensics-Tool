"""Windows Firewall log (``pfirewall.log``, W3C-like extended format).

The ``#Fields:`` directive defines the column order; ``#Time Format: Local`` (the default)
means timestamps are machine local time, recorded in ``attrs.time_is_local``. ``-`` means
"no value". Output: ``windows:firewall_log:entry``.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import TextLogParser
from veritas.timeline.schema import NS, Event

RECORDED = "Content Modification Time"  # plaso: last_written_time
DEFAULT_FIELDS = ["date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port", "size",
                  "tcpflags", "tcpsyn", "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path"]
INT_FIELDS = {"src-port", "dst-port", "size", "tcpsyn", "tcpack", "tcpwin", "icmptype", "icmpcode", "pid"}


class WindowsFirewallParser(TextLogParser):
    name = "winfirewall"
    version = "1.0"
    source_short = "LOG"
    source_long = "Windows Firewall Log"
    head_regex = re.compile(r"#Software: Microsoft Windows Firewall")

    def begin(self, prov: Provenance) -> None:
        self.fields = list(DEFAULT_FIELDS)
        self.local = True

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        if not line.strip():
            return
        if line.startswith("#"):
            if line.startswith("#Fields:"):
                self.fields = line.split(":", 1)[1].split()
            elif line.startswith("#Time Format:"):
                self.local = "local" in line.lower()
            return
        values = line.split()
        if len(values) < 2:
            self.warn(f"line {lineno}: too few fields")
            return
        rec = dict(zip(self.fields, values))
        try:
            dt = datetime.strptime(f"{rec.get('date')} {rec.get('time')}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            self.warn(f"line {lineno}: bad date/time")
            return
        attrs: dict = {"time_is_local": self.local}
        for k, v in rec.items():
            if k in ("date", "time"):
                continue
            key = k.replace("-", "_")
            if v == "-":
                attrs[key] = None
            elif k in INT_FIELDS and v.isdigit():
                attrs[key] = int(v)
            else:
                attrs[key] = v
        msg = (f"{attrs.get('action')} [{attrs.get('protocol')}] From: {attrs.get('src_ip')} :{attrs.get('src_port')} "
               f"To: {attrs.get('dst_ip')} :{attrs.get('dst_port')}")
        yield self.event("windows:firewall_log:entry", RECORDED, msg,
                         int(dt.timestamp()) * NS, offset=lineno, attrs=attrs)


PARSERS = [WindowsFirewallParser]
