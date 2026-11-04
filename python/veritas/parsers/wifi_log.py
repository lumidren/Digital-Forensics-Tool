"""macOS ``/var/log/wifi.log`` (airportd).

``Day Mon dd HH:MM:SS.mmm <agent[pid]> function: text`` or ``... ***Starting Up***``. Year-less:
the year is inferred with :class:`veritas.parsers.text_log.YearTracker` (``Provenance.year_hint``
/ ``mtime_ns``; increments on month wrap). -> ``macos:wifi_log:entry`` (Added Time, plaso
vocabulary) with agent, function, text and a derived ``action`` for association/auto-join events
(``ssid`` when quoted).
"""
from __future__ import annotations

import re
from typing import Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import MONTH_ABBR, TextLogParser, YearTracker
from veritas.timeline.schema import Event

LINE = re.compile(r"^(?P<dow>Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) "
                  r"(?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d{1,6}))?\s+(?P<rest>.*)$")
AGENT = re.compile(r"^<(?P<agent>[^>\[]+)(?:\[(?P<pid>\d+)\])?>\s*(?:(?P<func>[A-Za-z_][\w:]*):\s*)?(?P<text>.*)$")
SSID = re.compile(r"[“\"](?P<ssid>[^”\"]+)[”\"]|ssid=(?P<ssid2>[^,\]]+)")
ADDED = "Added Time"


class WifiLogParser(TextLogParser):
    name = "macos_wifi"
    version = "1.0"
    source_short = "LOG"
    source_long = "macOS WiFi log"
    head_regex = re.compile(r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}\.\d{3} (<\w+\[\d+\]>|\*\*\*)", re.M)

    def begin(self, prov: Provenance) -> None:
        self.years = YearTracker(prov)

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        m = LINE.match(line)
        if not m:
            if line.strip():
                self.warn(f"line {lineno}: not a wifi.log line")
            return
        month = MONTH_ABBR.get(m.group("mon"))
        if month is None:
            self.warn(f"line {lineno}: bad month")
            return
        hh, mm, ss = (int(x) for x in m.group("time").split(":"))
        frac = (m.group("frac") or "").ljust(3, "0") if m.group("frac") else None
        ts = self.years.to_ns(month, int(m.group("day")), hh, mm, ss, frac)
        rest = m.group("rest")
        am = AGENT.match(rest)
        attrs = {"agent": None, "pid": None, "function": None, "text": rest, "year_source": self.years.source}
        if am:
            attrs.update({"agent": am.group("agent"), "pid": int(am.group("pid")) if am.group("pid") else None,
                          "function": am.group("func"), "text": am.group("text")})
        sm = SSID.search(attrs["text"] or "")
        if sm:
            attrs["ssid"] = sm.group("ssid") or sm.group("ssid2")
        func = attrs["function"] or ""
        if "AutoJoin" in func or "Assoc" in func:
            attrs["action"] = f"{func}: {attrs.get('ssid') or ''}".strip()
        msg = f"Agent: {attrs['agent']} Function: {attrs['function']} Log: {attrs['text']}"
        yield self.event("macos:wifi_log:entry", ADDED, msg, ts, offset=lineno, attrs=attrs)


PARSERS = [WifiLogParser]
