"""systemd unit files (``*.service``, ``*.timer``, ``*.socket``, ``*.path``...).

INI-style sections; repeated keys (``ExecStartPre=``) accumulate; ``\\``-continued lines are
joined. One ``linux:systemd:unit`` event per file, timed by ``Provenance.mtime_ns`` (the
acquired file modification time) when supplied, else ``Not a time``. Persistence-relevant keys
are surfaced in attrs: ExecStart/ExecStartPre/ExecStartPost/ExecStop, User, Group, WantedBy,
RequiredBy, OnCalendar, OnBootSec, Restart, Type, Description, EnvironmentFile. ``attrs.suspicious``
flags executables under /tmp, /dev/shm, /var/tmp or hidden paths and shell download idioms.
"""
from __future__ import annotations

import re
from typing import Any, Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import TextLogParser, is_text
from veritas.timeline.schema import Desc, Event

UNIT_EXTS = (".service", ".timer", ".socket", ".path", ".mount", ".target", ".automount", ".slice", ".scope")
SECTION = re.compile(r"^\s*\[(?P<name>[^\]]+)\]\s*$")
KV = re.compile(r"^\s*(?P<k>[A-Za-z0-9]+)\s*=\s*(?P<v>.*)$")
KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload", "User", "Group", "WantedBy",
        "RequiredBy", "OnCalendar", "OnBootSec", "OnUnitActiveSec", "Restart", "Type", "Description",
        "EnvironmentFile", "Environment", "WorkingDirectory", "ListenStream", "Unit")
SUSPICIOUS = re.compile(r"(^|[\s=\"'])(/tmp/|/dev/shm/|/var/tmp/)|/\.[^/\s]+|(curl|wget)[^|;]*\|\s*(ba)?sh|/dev/tcp/|base64\s+-d", re.I)


class SystemdUnitParser(TextLogParser):
    name = "systemd_unit"
    version = "1.0"
    source_short = "LOG"
    source_long = "systemd unit file"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return path.lower().endswith(UNIT_EXTS) and is_text(head_bytes)

    def begin(self, prov: Provenance) -> None:
        self.section = ""
        self.values: dict[str, list[str]] = {}
        self.cont = ""
        self.unit = prov.evidence_path.replace("\\", "/").rsplit("/", 1)[-1]
        self.mtime = prov.mtime_ns

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        if self.cont:
            line = self.cont + line.lstrip()
            self.cont = ""
        if line.endswith("\\"):
            self.cont = line[:-1].rstrip() + " "
            return
        s = line.strip()
        if not s or s[0] in "#;":
            return
        m = SECTION.match(line)
        if m:
            self.section = m.group("name")
            return
        m = KV.match(line)
        if m and m.group("k") in KEYS:
            key = m.group("k")
            if m.group("v") == "" and key.startswith("Exec"):
                self.values.pop(key, None)  # empty assignment resets the list
            elif len(self.values.setdefault(key, [])) < 256:
                self.values[key].append(m.group("v"))
        return
        yield  # pragma: no cover - generator

    def finish(self) -> Iterator[Event]:
        if not self.values:
            return
        attrs: dict[str, Any] = {"unit": self.unit}
        for k in KEYS:
            if k in self.values:
                v = self.values[k]
                attrs[_snake(k)] = v if k.startswith("Exec") or k in ("Environment", "WantedBy", "RequiredBy") else v[-1]
        execs = " ".join(" ".join(self.values.get(k, [])) for k in KEYS if k.startswith("Exec"))
        attrs["suspicious"] = bool(SUSPICIOUS.search(execs))
        msg = f"systemd unit {self.unit}: ExecStart={' ; '.join(self.values.get('ExecStart', []))}"
        ts = self.mtime
        yield self.event("linux:systemd:unit", Desc.MODIFICATION if ts else Desc.NOT_A_TIME, msg, ts, offset=0,
                         attrs=attrs, user=attrs.get("user"))


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


PARSERS = [SystemdUnitParser]
