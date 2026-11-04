"""crontab files (``/etc/crontab``, ``/etc/cron.d/*``, ``/var/spool/cron/crontabs/<user>``).

Each schedule line becomes a ``linux:cron:entry`` inventory event (``Not a time`` unless the
caller supplies ``Provenance.mtime_ns``, in which case the file modification time is used with
``Content Modification Time``). System crontabs (``/etc/crontab``, ``/etc/cron.d``) have a user
field after the five schedule fields; user crontabs do not, and the owning user is taken from
the file name. ``@reboot``/``@daily``... specials, ``VAR=value`` environment lines and comments
are handled; ``attrs.suspicious`` flags download-and-execute and reverse-shell idioms.
"""
from __future__ import annotations

import re
from typing import Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import TextLogParser, detect_encoding, is_text
from veritas.timeline.schema import Desc, Event

FIELD = r"[\d\*/,\-A-Za-z]+"
SCHEDULE = re.compile(rf"^\s*(?P<sched>{FIELD}\s+{FIELD}\s+{FIELD}\s+{FIELD}\s+{FIELD})\s+(?P<rest>.+)$")
SPECIAL = re.compile(r"^\s*(?P<sched>@(?:reboot|yearly|annually|monthly|weekly|daily|midnight|hourly))\s+(?P<rest>.+)$")
ENV = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
SUSPICIOUS = re.compile(r"(curl|wget)[^|;]*\|\s*(ba|z|da)?sh|/dev/tcp/|\bnc(at)?\b.*\s-e\s|base64\s+(-d|--decode)|"
                        r"python[23]?\s+-c|perl\s+-e|/tmp/|/dev/shm/|chmod\s+\+x", re.I)


class CrontabParser(TextLogParser):
    name = "crontab"
    version = "1.0"
    source_short = "LOG"
    source_long = "Crontab"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        p = path.replace("\\", "/").lower()
        if not is_text(head_bytes):
            return False
        if "/cron.d/" in p or p.endswith("/crontab") or "/crontabs/" in p or p.rsplit("/", 1)[-1] == "crontab":
            return True
        codec, bom = detect_encoding(head_bytes)
        lines = [ln for ln in head_bytes[bom:].decode(codec, "replace").splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#") and not ENV.match(ln)]
        return bool(lines) and all(SCHEDULE.match(ln) or SPECIAL.match(ln) for ln in lines[:5])

    def begin(self, prov: Provenance) -> None:
        p = prov.evidence_path.replace("\\", "/")
        self.system = "/etc/" in p or p.endswith("crontab") and "/crontabs/" not in p
        self.file_user = p.rsplit("/", 1)[-1] if "/crontabs/" in p or "/spool/cron/" in p else None
        self.env: dict[str, str] = {}
        self.mtime = prov.mtime_ns

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        s = line.strip()
        if not s or s.startswith("#"):
            return
        m = SPECIAL.match(line) or SCHEDULE.match(line)
        if not m:
            e = ENV.match(line)
            if e:
                self.env[e.group(1)] = e.group(2)
            else:
                self.warn(f"line {lineno}: not a crontab entry")
            return
        rest = m.group("rest").strip()
        user = self.file_user
        if self.system:
            parts = rest.split(None, 1)
            if len(parts) == 2:
                user, rest = parts
        attrs = {"schedule": " ".join(m.group("sched").split()), "user": user, "command": rest,
                 "environment": dict(sorted(self.env.items())), "suspicious": bool(SUSPICIOUS.search(rest)),
                 "system_crontab": self.system}
        ts = self.mtime
        yield self.event("linux:cron:entry", Desc.MODIFICATION if ts else Desc.NOT_A_TIME,
                         f"Cron [{attrs['schedule']}] {user or ''}: {rest}", ts, offset=lineno, attrs=attrs, user=user)


PARSERS = [CrontabParser]
