"""Package manager logs.

* ``dpkg.log``: ``YYYY-MM-DD HH:MM:SS <action> ...`` (install/upgrade/remove/purge/configure/
  trigproc/status/conffile/startup) -> ``linux:dpkg_log:entry`` (``Added Time``, plaso vocabulary).
* apt ``history.log``: blank-line separated blocks with ``Start-Date``, ``Commandline``,
  ``Requested-By``, ``Install``/``Upgrade``/``Remove``/``Purge``/``Downgrade``/``Reinstall``,
  ``Error``, ``End-Date`` -> ``linux:apt_history_log:entry`` (Start Time, End Time). Package
  lists are split on ``), `` into a list.
* ``dnf.log`` / ``dnf.rpm.log`` / ``yum.log``: ``<ISO time> <LEVEL> <message>`` (dnf) or
  ``Mmm dd HH:MM:SS Installed: pkg`` (yum; year from ``Provenance.year_hint``/``mtime_ns``)
  -> ``linux:dnf_log:entry`` / ``linux:yum_log:entry``.
Times are local machine time as written (``attrs.time_is_local``).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import TextLogParser, detect_encoding, is_text
from veritas.timeline.schema import NS, Desc, Event, iso_to_ns

DPKG = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<body>(?P<action>\S+).*)$")
APT_KV = re.compile(r"^(?P<k>Start-Date|End-Date|Commandline|Requested-By|Install|Upgrade|Remove|Purge|Downgrade|"
                    r"Reinstall|Error):\s*(?P<v>.*)$")
DNF = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<level>[A-Z]+)\s+(?P<msg>.*)$")
YUM = re.compile(r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
                 r"(?P<action>Installed|Updated|Erased|Dep-Installed|Obsoleted|Reinstalled|Downgraded): (?P<pkg>.*)$")
MONTHS = {m: i for i, m in enumerate(["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def _local(text: str, fmt: str) -> int | None:
    try:
        return int(datetime.strptime(" ".join(text.split()), fmt).replace(tzinfo=timezone.utc).timestamp()) * NS
    except ValueError:
        return None


def _first_line(head: bytes) -> str:
    """First non-blank line of the head bytes."""
    codec, bom = detect_encoding(head)
    for line in head[bom:].decode(codec, "replace").splitlines():
        if line.strip():
            return line.strip()
    return ""


class DpkgLogParser(TextLogParser):
    name = "dpkg"
    version = "1.0"
    source_long = "dpkg log"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return is_text(head_bytes) and DPKG.match(_first_line(head_bytes)) is not None and "dpkg" in path.lower()

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        m = DPKG.match(line)
        if not m:
            if line.strip():
                self.warn(f"line {lineno}: not a dpkg log line")
            return
        parts = m.group("body").split()
        attrs = {"body": m.group("body"), "action": parts[0], "time_is_local": True}
        if parts[0] in ("install", "upgrade", "remove", "purge", "configure", "trigproc") and len(parts) >= 2:
            attrs["package"] = parts[1]
            attrs["old_version"] = parts[2] if len(parts) > 2 and parts[0] != "configure" else None
            attrs["new_version"] = parts[3] if len(parts) > 3 else (parts[2] if parts[0] == "configure" and len(parts) > 2 else None)
        elif parts[0] == "status" and len(parts) >= 4:
            attrs.update({"status": parts[1], "package": parts[2], "new_version": parts[3]})
        yield self.event("linux:dpkg_log:entry", "Added Time", m.group("body"),
                         _local(m.group("ts"), "%Y-%m-%d %H:%M:%S"), offset=lineno, attrs=attrs)


class AptHistoryParser(TextLogParser):
    name = "apt_history"
    version = "1.0"
    source_long = "APT history log"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return is_text(head_bytes) and _first_line(head_bytes).startswith("Start-Date:")

    def begin(self, prov: Provenance) -> None:
        self.block: dict | None = None

    def _flush(self) -> Iterator[Event]:
        if self.block is None:
            return
        b, self.block = self.block, None
        attrs = {"command_line": b.get("Commandline"), "requested_by": b.get("Requested-By"),
                 "error": b.get("Error"), "time_is_local": True}
        for k in ("Install", "Upgrade", "Remove", "Purge", "Downgrade", "Reinstall"):
            if k in b:
                attrs[k.lower() + "_packages"] = [p if p.endswith(")") else p + ")" for p in b[k].split("), ") if p][:10000]
        msg = f"{b.get('Commandline') or ''}"
        start = _local(b.get("Start-Date", ""), "%Y-%m-%d %H:%M:%S")
        end = _local(b.get("End-Date", ""), "%Y-%m-%d %H:%M:%S")
        if start is not None:
            yield self.event("linux:apt_history_log:entry", Desc.START, msg, start, offset=b["lineno"], attrs=attrs)
        if end is not None:
            yield self.event("linux:apt_history_log:entry", Desc.END, msg, end, offset=b["lineno"], attrs=attrs)
        if start is None and end is None:
            yield self.event("linux:apt_history_log:entry", Desc.NOT_A_TIME, msg, None, offset=b["lineno"], attrs=attrs)

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        if not line.strip():
            yield from self._flush()
            return
        m = APT_KV.match(line)
        if not m:
            self.warn(f"line {lineno}: unexpected apt history line")
            return
        if m.group("k") == "Start-Date":
            yield from self._flush()
            self.block = {"lineno": lineno}
        if self.block is None:
            self.block = {"lineno": lineno}
        self.block[m.group("k")] = m.group("v")

    def finish(self) -> Iterator[Event]:
        yield from self._flush()


class DnfYumLogParser(TextLogParser):
    name = "dnf_yum"
    version = "1.0"
    source_long = "dnf/yum log"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        n = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        return is_text(head_bytes) and (n.startswith("dnf") or n.startswith("yum")) and ".log" in n

    def begin(self, prov: Provenance) -> None:
        if prov.year_hint:
            self.year = prov.year_hint
        elif prov.mtime_ns:
            self.year = datetime.fromtimestamp(prov.mtime_ns // NS, tz=timezone.utc).year
        else:
            self.year = 1970
        self.last_month = 0

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        m = DNF.match(line)
        if m:
            yield self.event("linux:dnf_log:entry", Desc.MODIFICATION, m.group("msg"), iso_to_ns(m.group("ts")),
                             offset=lineno, attrs={"level": m.group("level"), "body": m.group("msg")})
            return
        m = YUM.match(line)
        if m:
            month = MONTHS[m.group("mon")]
            if self.last_month and month < self.last_month:
                self.year += 1
            self.last_month = month
            ts = _local(f"{self.year} {month} {m.group('day')} {m.group('time')}", "%Y %m %d %H:%M:%S")
            yield self.event("linux:yum_log:entry", Desc.MODIFICATION, f"{m.group('action')}: {m.group('pkg')}", ts,
                             offset=lineno, attrs={"action": m.group("action"), "package": m.group("pkg"), "time_is_local": True})


PARSERS = [DpkgLogParser, AptHistoryParser, DnfYumLogParser]
