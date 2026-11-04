"""Shell history files.

* bash ``.bash_history``: with ``HISTTIMEFORMAT`` set, each command is preceded by a ``#<epoch>``
  line. Lines without a preceding timestamp line are continuation lines of the previous
  command (multi-line commands); a file with no timestamp lines at all yields ``Not a time``
  events per command line. -> ``bash:history:entry``
* zsh extended history: ``: <epoch>:<duration>;<command>``; a trailing backslash continues
  the command on the next line. -> ``shell:zsh:history``
* fish ``fish_history``: YAML-ish ``- cmd: <command>`` / ``  when: <epoch>`` / ``  paths:``
  blocks; parsed line by line (no YAML loader, so no object construction). -> ``fish:history:entry``
"""
from __future__ import annotations

import re
from typing import Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import TextLogParser, detect_encoding, is_text
from veritas.timeline.schema import NS, Desc, Event

BASH_TS = re.compile(r"^#(\d{9,11})\s*$")
ZSH_LINE = re.compile(r"^: (\d{9,11}):(\d+);(.*)$")
FISH_CMD = re.compile(r"^- cmd: ?(.*)$")
FISH_WHEN = re.compile(r"^\s+when: (\d+)\s*$")
FISH_PATH = re.compile(r"^\s+- (.*)$")


def _head_lines(head: bytes, n: int = 6) -> list[str]:
    codec, bom = detect_encoding(head)
    return head[bom:].decode(codec, "replace").splitlines()[:n]


class BashHistoryParser(TextLogParser):
    name = "bash_history"
    version = "1.0"
    source_short = "HIST"
    source_long = "Bash History"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        if not is_text(head_bytes):
            return False
        lines = _head_lines(head_bytes)
        return (bool(lines) and BASH_TS.match(lines[0]) is not None) or "bash_history" in path.replace("\\", "/").rsplit("/", 1)[-1]

    def begin(self, prov: Provenance) -> None:
        self.ts: int | None = None
        self.cmd: list[str] = []
        self.start = 0
        self.saw_ts = False

    def _flush(self) -> Iterator[Event]:
        if not self.cmd:
            return
        command = "\n".join(self.cmd)
        self.cmd = []
        yield self.event("bash:history:entry", Desc.MODIFICATION, f"Command executed: {command}", self.ts,
                         offset=self.start, attrs={"command": command, "has_timestamp": self.ts is not None})

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        m = BASH_TS.match(line)
        if m:
            yield from self._flush()
            self.saw_ts = True
            self.ts = int(m.group(1)) * NS
            return
        if not self.saw_ts:
            # No HISTTIMEFORMAT: one command per line, no time.
            if line.strip():
                self.cmd, self.start, self.ts = [line], lineno, None
                yield from self._flush()
            return
        if not self.cmd:
            self.start = lineno
        self.cmd.append(line)

    def finish(self) -> Iterator[Event]:
        yield from self._flush()


class ZshHistoryParser(TextLogParser):
    name = "zsh_extended_history"
    version = "1.0"
    source_short = "HIST"
    source_long = "Zsh Extended History"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        if not is_text(head_bytes):
            return False
        lines = _head_lines(head_bytes)
        return bool(lines) and ZSH_LINE.match(lines[0]) is not None

    def begin(self, prov: Provenance) -> None:
        self.cur: dict | None = None

    def _flush(self) -> Iterator[Event]:
        if self.cur is None:
            return
        c, self.cur = self.cur, None
        command = "\n".join(c["lines"])
        yield self.event("shell:zsh:history", Desc.MODIFICATION, f"{command} Time elapsed: {c['elapsed']} seconds",
                         c["ts"], offset=c["lineno"], attrs={"command": command, "elapsed_seconds": c["elapsed"]})

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        m = ZSH_LINE.match(line)
        if m and (self.cur is None or not self.cur["lines"][-1].endswith("\\")):
            yield from self._flush()
            self.cur = {"ts": int(m.group(1)) * NS, "elapsed": int(m.group(2)), "lines": [m.group(3)], "lineno": lineno}
            return
        if self.cur is not None:
            self.cur["lines"].append(line)
        elif line.strip():
            self.warn(f"line {lineno}: not a zsh extended history line")

    def finish(self) -> Iterator[Event]:
        yield from self._flush()


class FishHistoryParser(TextLogParser):
    name = "fish_history"
    version = "1.0"
    source_short = "HIST"
    source_long = "Fish History"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        if not is_text(head_bytes):
            return False
        lines = _head_lines(head_bytes, 2)
        return len(lines) >= 1 and FISH_CMD.match(lines[0]) is not None

    def begin(self, prov: Provenance) -> None:
        self.cur: dict | None = None
        self.in_paths = False

    def _flush(self) -> Iterator[Event]:
        if self.cur is None:
            return
        c, self.cur = self.cur, None
        cmd = c["cmd"].replace("\\n", "\n").replace("\\\\", "\\")
        yield self.event("fish:history:entry", Desc.MODIFICATION, f"Command executed: {cmd}", c["ts"],
                         offset=c["lineno"], attrs={"command": cmd, "paths": c["paths"]})

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        m = FISH_CMD.match(line)
        if m:
            yield from self._flush()
            self.cur = {"cmd": m.group(1), "ts": None, "paths": [], "lineno": lineno}
            self.in_paths = False
            return
        if self.cur is None:
            if line.strip():
                self.warn(f"line {lineno}: unexpected fish history line")
            return
        m = FISH_WHEN.match(line)
        if m:
            self.cur["ts"] = int(m.group(1)) * NS
            self.in_paths = False
            return
        if line.strip() == "paths:":
            self.in_paths = True
            return
        m = FISH_PATH.match(line)
        if m and self.in_paths and len(self.cur["paths"]) < 1000:
            self.cur["paths"].append(m.group(1))

    def finish(self) -> Iterator[Event]:
        yield from self._flush()


PARSERS = [BashHistoryParser, ZshHistoryParser, FishHistoryParser]
