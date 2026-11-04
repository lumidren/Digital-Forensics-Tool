"""macOS application firewall log (``/var/log/appfirewall.log``).

``Mmm dd HH:MM:SS host socketfilterfw[pid] <Level>: Process: Action PROTO STATE (in:n out:m)``.
Year-less (see :class:`veritas.parsers.text_log.YearTracker`). -> ``macos:appfirewall_log:entry``
(Added Time, plaso vocabulary) with computer_name, agent, status, process_name, action.
"""
from __future__ import annotations

import re
from typing import Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import MONTH_ABBR, TextLogParser, YearTracker
from veritas.timeline.schema import Event

LINE = re.compile(r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
                  r"(?P<agent>[^\s\[]+)\[(?P<pid>\d+)\] <(?P<status>\w+)>: (?P<body>.*)$")
BODY = re.compile(r"^(?P<process>[^:]+): (?P<action>.*)$")
REPEATED = re.compile(r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<msg>--- last message repeated \d+ times? ---)\s*$")


class AppFirewallParser(TextLogParser):
    name = "mac_appfirewall_log"
    version = "1.0"
    source_short = "LOG"
    source_long = "macOS App Firewall"
    head_regex = re.compile(r"socketfilterfw\[\d+\] <\w+>:")

    def begin(self, prov: Provenance) -> None:
        self.years = YearTracker(prov)

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        m = LINE.match(line)
        rm = REPEATED.match(line) if not m else None
        if rm:
            month = MONTH_ABBR.get(rm.group("mon"))
            hh, mm, ss = (int(x) for x in rm.group("time").split(":"))
            ts = self.years.to_ns(month, int(rm.group("day")), hh, mm, ss) if month else None
            yield self.event("macos:appfirewall_log:entry", "Added Time", rm.group("msg"), ts, offset=lineno,
                             attrs={"action": rm.group("msg"), "year_source": self.years.source})
            return
        if not m:
            if line.strip():
                self.warn(f"line {lineno}: not an appfirewall line")
            return
        month = MONTH_ABBR.get(m.group("mon"))
        if month is None:
            self.warn(f"line {lineno}: bad month")
            return
        hh, mm, ss = (int(x) for x in m.group("time").split(":"))
        ts = self.years.to_ns(month, int(m.group("day")), hh, mm, ss)
        bm = BODY.match(m.group("body"))
        attrs = {"computer_name": m.group("host"), "agent": m.group("agent"), "pid": int(m.group("pid")),
                 "status": m.group("status"), "process_name": bm.group("process") if bm else None,
                 "action": bm.group("action").strip() if bm else m.group("body"), "year_source": self.years.source}
        msg = f"Computer: {attrs['computer_name']} Agent: {attrs['agent']} Status: {attrs['status']} " \
              f"Process name: {attrs['process_name']} Log: {attrs['action']}"
        yield self.event("macos:appfirewall_log:entry", "Added Time", msg, ts, offset=lineno, attrs=attrs,
                         host=str(attrs["computer_name"]) if attrs["computer_name"] is not None else None)


PARSERS = [AppFirewallParser]
