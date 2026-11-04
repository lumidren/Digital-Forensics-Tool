"""Linux audit log (``/var/log/audit/audit.log``).

Each line is ``type=<TYPE> msg=audit(<epoch>.<ms>:<serial>): key=value ...``. Records sharing a
serial number form one audit event (SYSCALL + EXECVE + CWD + PATH* + PROCTITLE ...). Records are
grouped by serial (an LRU of 256 open groups; a group is flushed when it falls out of the LRU or
at end of file) and one ``linux:auditd:event`` is emitted per serial, typed by its primary record
(the first record type in the group) in ``attrs.record_type``.

Values: ``key="quoted"`` strings are unquoted; unquoted even-length hex strings in fields that
the kernel hex-encodes (EXECVE ``aN``, ``proctitle``, ``cwd``, ``name``, ``comm``, ``exe``,
``data``) are decoded (NULs become spaces in proctitle). EXECVE ``aN`` arguments are joined into
``attrs.command_line``. USER_* / CRED_* records carry a nested ``msg='k=v ...'`` which is parsed
too (op, acct, exe, hostname, addr, terminal, res). Enriched logs (``\\x1d``-separated
``UID="root"`` translations) are accepted and the translations kept under ``attrs.enriched``.
"""
from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any, Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import TextLogParser
from veritas.timeline.schema import Desc, Event

HEADER = re.compile(r"^(?:node=(?P<node>\S+) )?type=(?P<type>\S+) msg=audit\((?P<sec>\d+)\.(?P<ms>\d{1,3}):(?P<serial>\d+)\):\s?(?P<body>.*)$")
KV = re.compile(r"""(?P<k>[A-Za-z0-9_\-]+)=(?P<v>"[^"]*"|'[^']*'|\S*)""")
HEXFIELDS = re.compile(r"^(a\d+|proctitle|cwd|name|comm|exe|data|path|cmd)$")
HEXVAL = re.compile(r"^(?:[0-9A-F]{2})+$")
OPEN_GROUPS = 256
MAX_RECORDS_PER_GROUP = 512


def _kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in KV.finditer(text):
        v = m.group("v")
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out.setdefault(m.group("k"), v)
    return out


def _decode(key: str, value: str) -> str:
    if HEXFIELDS.match(key) and len(value) >= 2 and HEXVAL.match(value) and value not in ("00",):
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            return value
        text = raw.decode("utf-8", "replace")
        return text.replace("\x00", " ").strip() if key == "proctitle" else text
    return value


class AuditdParser(TextLogParser):
    name = "auditd"
    version = "1.0"
    source_short = "LOG"
    source_long = "Linux audit log"
    head_regex = re.compile(r"^(node=\S+ )?type=\S+ msg=audit\(\d+\.\d+:\d+\):", re.M)

    def begin(self, prov: Provenance) -> None:
        self.groups: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        if not line.strip():
            return
        enriched = None
        if "\x1d" in line:
            line, enriched = line.split("\x1d", 1)
        m = HEADER.match(line)
        if not m:
            self.warn(f"line {lineno}: not an audit record")
            return
        key = (m.group("node") or "", m.group("serial"))
        group = self.groups.get(key)
        if group is None:
            group = {"sec": int(m.group("sec")), "ms": int(m.group("ms").ljust(3, "0")), "serial": int(m.group("serial")),
                     "node": m.group("node"), "lineno": lineno, "records": []}
            self.groups[key] = group
            while len(self.groups) > OPEN_GROUPS:
                _, old = self.groups.popitem(last=False)
                yield self._emit(old)
        else:
            self.groups.move_to_end(key)
        if len(group["records"]) < MAX_RECORDS_PER_GROUP:
            fields = _kv(m.group("body"))
            nested = None
            mm = re.search(r"msg='([^']*)'", m.group("body"))
            if mm:
                nested = _kv(mm.group(1))
            group["records"].append({"type": m.group("type"), "fields": fields, "nested": nested,
                                     "enriched": _kv(enriched) if enriched else None})

    def finish(self) -> Iterator[Event]:
        groups = sorted(self.groups.values(), key=lambda g: g["lineno"])
        self.groups.clear()
        for g in groups:
            yield self._emit(g)

    def _emit(self, g: dict[str, Any]) -> Event:
        recs = g["records"]
        primary = recs[0]["type"] if recs else "UNKNOWN"
        attrs: dict[str, Any] = {"serial": g["serial"], "record_type": primary, "record_types": [r["type"] for r in recs],
                                 "node": g["node"]}
        paths = []
        argv: dict[int, str] = {}
        enriched: dict[str, str] = {}
        for r in recs:
            f = {k: _decode(k, v) for k, v in r["fields"].items() if k != "msg"}
            t = r["type"]
            if r["enriched"]:
                enriched.update(r["enriched"])
            if t == "EXECVE":
                for k, v in f.items():
                    if re.fullmatch(r"a\d+", k):
                        argv[int(k[1:])] = v
                attrs["argc"] = int(f["argc"]) if f.get("argc", "").isdigit() else None
            elif t == "PATH":
                paths.append({k: f.get(k) for k in ("item", "name", "inode", "mode", "nametype", "ouid") if k in f})
            elif t == "CWD":
                attrs["cwd"] = f.get("cwd")
            elif t == "PROCTITLE":
                attrs["proctitle"] = f.get("proctitle")
            else:
                for k, v in f.items():
                    attrs.setdefault(k, v)
            if r["nested"]:
                for k, v in r["nested"].items():
                    attrs.setdefault(k, _decode(k, v))
        if argv:
            attrs["argv"] = [argv[i] for i in sorted(argv)]
            attrs["command_line"] = " ".join(attrs["argv"])
        if paths:
            attrs["paths"] = paths
        if enriched:
            attrs["enriched"] = enriched
        ts = g["sec"] * 1_000_000_000 + g["ms"] * 1_000_000
        summary = attrs.get("command_line") or attrs.get("proctitle") or attrs.get("exe") or attrs.get("op") or ""
        msg = f"{primary} serial={g['serial']}"
        for k in ("auid", "uid", "acct", "res", "success", "key"):
            if attrs.get(k) not in (None, ""):
                msg += f" {k}={attrs[k]}"
        if summary:
            msg += f" {summary}"
        user = enriched.get("UID") or attrs.get("acct")
        return self.event("linux:auditd:event", Desc.EVENT, msg, ts, offset=g["lineno"], attrs=attrs,
                          host=g["node"], user=user)


PARSERS = [AuditdParser]
