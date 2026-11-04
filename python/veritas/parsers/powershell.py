"""PowerShell artifacts.

* ``ConsoleHost_history.txt`` (PSReadLine): one command per line, no timestamps. Every line
  becomes a ``powershell:history:entry`` event with ``Not a time`` and its 1-based line index;
  a trailing backtick continues the command on the next line.
* Transcripts (``PowerShell_transcript.*.txt``): header block delimited by ``****`` lines
  holding ``Start time: yyyymmddHHMMSS``, ``Username``, ``RunAs User``, ``Machine``, ``Host
  Application``, ``Process ID``; then ``PS <cwd>> command`` lines followed by output. Each
  command becomes ``powershell:transcript_log:entry`` timed at the session start time (local
  time of the machine as written; flagged with ``attrs.time_is_local``). "Command start
  time:" lines (when ``-IncludeInvocationHeader`` was used) give per-command timestamps.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import TextLogParser
from veritas.timeline.schema import NS, Desc, Event

STAR = re.compile(r"^\*{10,}\s*$")
HEADER_KV = re.compile(r"^([A-Za-z][A-Za-z ]+?):\s*(.*)$")
PROMPT = re.compile(r"^PS (?P<cwd>[^>]*)>\s?(?P<cmd>.*)$")


def _compact_time(text: str) -> int | None:
    text = text.strip()
    if not re.fullmatch(r"\d{14}", text):
        return None
    try:
        dt = datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(dt.timestamp()) * NS


class PowerShellTranscriptParser(TextLogParser):
    name = "powershell_transcript"
    version = "1.0"
    source_short = "LOG"
    source_long = "PowerShell transcript"
    head_regex = re.compile(r"(Windows PowerShell transcript start|PowerShell transcript start)")

    def begin(self, prov: Provenance) -> None:
        self.header: dict[str, str] = {}
        self.in_header = False
        self.session_start: int | None = None
        self.cmd_time: int | None = None
        self.pending: tuple[int, str, str] | None = None
        self.output: list[str] = []

    def _flush(self) -> Iterator[Event]:
        if self.pending is None:
            return
        lineno, cwd, cmd = self.pending
        self.pending = None
        ts = self.cmd_time or self.session_start
        attrs = {
            "command": cmd, "working_directory": cwd, "username": self.header.get("Username"),
            "runas_user": self.header.get("RunAs User"), "machine": self.header.get("Machine"),
            "host_application": self.header.get("Host Application"), "process_identifier": self.header.get("Process ID"),
            "ps_version": self.header.get("PSVersion"), "output": "\n".join(self.output)[:4096],
            "time_is_local": True, "time_source": "command" if self.cmd_time else "session_start",
        }
        self.output = []
        self.cmd_time = None
        host = (self.header.get("Machine") or "").split(" ", 1)[0] or None
        yield self.event("powershell:transcript_log:entry", Desc.START if ts else Desc.NOT_A_TIME,
                         f"{self.header.get('Username', '')} {cwd}> {cmd}", ts, offset=lineno, attrs=attrs,
                         host=host, user=self.header.get("Username"))

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        if STAR.match(line):
            yield from self._flush()
            if self.in_header and self.header:
                self.in_header = False  # closing delimiter of the header block
            return
        if line.startswith("Windows PowerShell transcript start") or line.startswith("PowerShell transcript start"):
            yield from self._flush()
            self.in_header = True
            self.header = {}
            return
        if line.startswith("Windows PowerShell transcript end") or line.startswith("PowerShell transcript end"):
            yield from self._flush()
            return
        m = HEADER_KV.match(line)
        if self.in_header and m:
            key, val = m.group(1).strip(), m.group(2).strip()
            self.header[key] = val
            if key == "Start time":
                self.session_start = _compact_time(val)
            return
        if m and m.group(1) == "Command start time":
            yield from self._flush()
            self.cmd_time = _compact_time(m.group(2))
            return
        pm = PROMPT.match(line)
        if pm:
            self.in_header = False
            yield from self._flush()
            self.pending = (lineno, pm.group("cwd"), pm.group("cmd"))
            return
        if self.pending is not None and len(self.output) < 200:
            self.output.append(line)

    def finish(self) -> Iterator[Event]:
        yield from self._flush()


class PowerShellHistoryParser(TextLogParser):
    name = "powershell_history"
    version = "1.0"
    source_short = "LOG"
    source_long = "PSReadLine history"
    filename_hints = ("consolehost_history",)

    def matches(self, path: str, head_bytes: bytes) -> bool:
        base = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        return base.endswith("_history.txt") and "consolehost" in base

    def begin(self, prov: Provenance) -> None:
        self.buffer: list[str] = []
        self.start_line = 0

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        if not self.buffer:
            self.start_line = lineno
        self.buffer.append(line)
        if line.endswith("`"):
            return
        yield from self.finish()

    def finish(self) -> Iterator[Event]:
        if not self.buffer:
            return
        cmd = "\n".join(self.buffer)
        self.buffer = []
        if not cmd.strip():
            return
        yield self.event("powershell:history:entry", Desc.NOT_A_TIME, cmd, None, offset=self.start_line,
                         attrs={"command": cmd, "line_index": self.start_line})


PARSERS = [PowerShellTranscriptParser, PowerShellHistoryParser]
