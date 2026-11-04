"""Syslog text files: traditional BSD, rsyslog high-precision (ISO 8601) and RFC 5424.

Line formats recognised (an optional ``<PRI>`` prefix is accepted on all of them):

* ``Mmm dd HH:MM:SS[.ffffff] host reporter[pid]: message``  (BSD / RFC 3164, no year)
* ``YYYY-MM-DDTHH:MM:SS[.ffffff](Z|+hh:mm) host reporter[pid]: message`` (rsyslog RSYSLOG_FileFormat)
* ``<PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD|-] MSG`` (RFC 5424 / RSYSLOG_SyslogProtocol23Format)
* macOS flavour ``reporter[pid] <Level>: message``.

Lines that match none of these are continuation lines of the previous record (multi-line
messages) and are appended to it.

Year inference for the year-less BSD format (documented contract):
``Provenance.year_hint`` if given, else the year of ``Provenance.mtime_ns`` (the file's
modification time recorded at acquisition), else 1970 with a warning. The first record gets
that year; whenever the month goes *backwards* (Dec -> Jan) the year is incremented, so a file
spanning a new year is ordered correctly. ``attrs.year_source`` records which rule applied so an
examiner can re-base the year. Nothing reads the wall clock. Timestamps without an offset are treated as UTC and flagged ``time_is_local``.

Sub-parsers on the message body produce plaso data types:
``syslog:ssh:login`` / ``failed_connection`` / ``opened_connection`` / ``invalid_user`` /
``closed_connection`` / ``received_disconnect``, ``syslog:cron:task_run``, ``syslog:sudo:command``
(``attrs.user``, ``command``, ``tty``, ``pwd``, ``target_user``), ``syslog:comment`` and
``syslog:line`` for everything else.
"""
from __future__ import annotations

import calendar
import re
from datetime import datetime, timezone
from typing import Any, Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import TextLogParser
from veritas.timeline.schema import NS, Desc, Event, iso_to_ns

MONTHS = {m: i for i, m in enumerate(calendar.month_abbr) if m}
PRI = r"(?:<(?P<pri>\d{1,3})>)?"
BSD = re.compile(PRI + r"(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+"
                 r"(?P<time>\d{2}:\d{2}:\d{2})(?P<frac>\.\d{1,9})?(?P<rest>.*)$")
ISO = re.compile(PRI + r"(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<rest>.*)$")
RFC5424 = re.compile(r"^<(?P<pri>\d{1,3})>(?P<ver>\d{1,2})\s+(?P<iso>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
                     r"(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)\s?(?P<msg>.*)$")
HOST_REST = re.compile(r"^\s+(?P<host>\S+)\s+(?P<body>.*)$")
REPORTER = re.compile(r"^(?P<rep>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?(?:\s+<(?P<level>\w+)>)?:\s?(?P<msg>.*)$")
COMMENT = re.compile(r"^:\s+(?P<msg>---.*---)\s*$")

SSH_PATTERNS = [
    ("syslog:ssh:login", re.compile(r"^Accepted (?P<authentication_method>\S+) for (?P<username>\S+) from (?P<address>\S+) "
                                     r"port (?P<port>\d+)(?:\s+(?P<protocol>ssh2?))?(?::\s+(?P<key_type>\S+)\s+(?P<fingerprint>\S+))?")),
    ("syslog:ssh:failed_connection", re.compile(r"^Failed (?P<authentication_method>\S+) for (?:invalid user )?(?P<username>\S+) "
                                                 r"from (?P<address>\S+) port (?P<port>\d+)(?:\s+(?P<protocol>ssh2?))?")),
    ("syslog:ssh:opened_connection", re.compile(r"^Connection from (?P<address>\S+) port (?P<port>\d+)")),
    ("syslog:ssh:invalid_user", re.compile(r"^Invalid user (?P<username>\S*) from (?P<address>\S+)(?: port (?P<port>\d+))?")),
    ("syslog:ssh:closed_connection", re.compile(r"^Connection closed by (?:(?:authenticating|invalid) user (?P<username>\S+) )?"
                                                 r"(?P<address>\S+) port (?P<port>\d+)")),
    ("syslog:ssh:received_disconnect", re.compile(r"^Received disconnect from (?P<address>\S+)(?: port (?P<port>\d+))?:?\s*(?P<reason>.*)")),
]
CRON_RUN = re.compile(r"^\((?P<username>[^)]+)\) CMD \((?P<command>.*)\)\s*$")
SUDO = re.compile(r"^\s*(?P<user>\S+)\s+:\s+(?P<fields>.*)$")


def _sudo_fields(text: str) -> dict[str, Any] | None:
    parts = [p.strip() for p in text.split(" ; ")]
    out: dict[str, Any] = {}
    error = None
    for p in parts:
        if "=" in p and p.split("=", 1)[0].isupper():
            k, v = p.split("=", 1)
            out[k.lower()] = v
        else:
            error = p
    if "command" not in out:
        return None
    if error:
        out["error"] = error
    return out


class SyslogParser(TextLogParser):
    name = "syslog"
    version = "1.0"
    source_short = "LOG"
    source_long = "Syslog"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        from veritas.parsers.text_log import detect_encoding, is_text

        if not is_text(head_bytes):
            return False
        codec, bom = detect_encoding(head_bytes)
        lines = head_bytes[bom:].decode(codec, "replace").splitlines()[:5]
        hits = sum(1 for ln in lines if _looks_like_syslog(ln))
        return bool(lines) and hits >= max(1, (len(lines) + 1) // 2)

    def begin(self, prov: Provenance) -> None:
        self.pending: dict[str, Any] | None = None
        self.last_month = 0
        self.year_source = "year_hint"
        if prov.year_hint:
            self.year = int(prov.year_hint)
        elif prov.mtime_ns:
            self.year = datetime.fromtimestamp(prov.mtime_ns // NS, tz=timezone.utc).year
            self.year_source = "file_mtime"
        else:
            self.year = 1970
            self.year_source = "default_1970"
            self.year_warned = False

    # -- record assembly -----------------------------------------------------------------
    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        if not line.strip():
            return
        rec = self._header(line)
        if rec is None:
            if self.pending is not None and len(self.pending["body"]) < 65536:
                self.pending["body"] += "\n" + line
            else:
                self.warn(f"line {lineno}: unrecognised syslog line")
            return
        yield from self.finish()
        rec["lineno"] = lineno
        self.pending = rec

    def finish(self) -> Iterator[Event]:
        if self.pending is None:
            return
        rec, self.pending = self.pending, None
        yield self._emit(rec)

    def _bsd_time(self, m: re.Match) -> tuple[int | None, bool]:
        month = MONTHS[m.group("mon")]
        if self.last_month and month < self.last_month:
            self.year += 1
        self.last_month = month
        if self.year_source == "default_1970" and not getattr(self, "year_warned", True):
            self.warn("no year hint or file mtime: year-less timestamps assumed to be 1970")
            self.year_warned = True
        hh, mm, ss = (int(x) for x in m.group("time").split(":"))
        try:
            dt = datetime(self.year, month, int(m.group("day")), hh, mm, ss, tzinfo=timezone.utc)
        except ValueError:
            return None, True
        frac = m.group("frac")
        ns = int((frac[1:] + "000000000")[:9]) if frac else 0
        return int(dt.timestamp()) * NS + ns, True

    def _header(self, line: str) -> dict[str, Any] | None:
        m = RFC5424.match(line)
        if m:
            ts = iso_to_ns(m.group("iso"))
            pri = int(m.group("pri"))
            return {"ts": ts, "local": False, "host": _nil(m.group("host")), "reporter": _nil(m.group("app")),
                    "pid": _int(m.group("pid")), "severity": pri & 7, "facility": pri >> 3, "level": None,
                    "body": m.group("msg"), "msgid": _nil(m.group("msgid")), "sd": _nil(m.group("sd")), "format": "rfc5424"}
        m = ISO.match(line)
        if m:
            hm = HOST_REST.match(" " + m.group("rest"))
            if not hm:
                return None
            ts = iso_to_ns(m.group("iso"))
            iso = m.group("iso")
            # iso_to_ns drops sub-microsecond digits; keep full ns precision.
            fm = re.search(r"\.(\d{7,9})", iso)
            if ts is not None and fm:
                ts = ts - (ts % 1000) + int((fm.group(1) + "000")[6:9])
            rec = {"ts": ts, "local": not re.search(r"(Z|[+-]\d{2}:?\d{2})$", iso), "host": hm.group("host"),
                   "format": "iso8601"}
            rec.update(_split_body(hm.group("body")))
            return _with_pri(rec, m.group("pri"))
        m = BSD.match(line)
        if m:
            rest = m.group("rest")
            cm = COMMENT.match(rest)
            if cm:
                ts, _ = self._bsd_time(m)
                return {"ts": ts, "local": True, "host": None, "reporter": None, "pid": None, "level": None,
                        "body": cm.group("msg"), "comment": True, "format": "bsd"}
            hm = HOST_REST.match(rest)
            if not hm:
                return None
            ts, _ = self._bsd_time(m)
            rec = {"ts": ts, "local": True, "host": hm.group("host"), "format": "bsd"}
            rec.update(_split_body(hm.group("body")))
            return _with_pri(rec, m.group("pri"))
        return None

    # -- event construction --------------------------------------------------------------
    def _emit(self, rec: dict[str, Any]) -> Event:
        body = rec.get("body") or ""
        reporter = rec.get("reporter") or ""
        attrs: dict[str, Any] = {
            "reporter": rec.get("reporter"), "pid": rec.get("pid"), "hostname": rec.get("host"), "body": body,
            "severity": rec.get("severity"), "facility": rec.get("facility"), "level": rec.get("level"),
            "time_is_local": rec.get("local", False), "line_format": rec.get("format"),
        }
        if rec.get("format") == "bsd":
            attrs["year_source"] = self.year_source
        for k in ("msgid", "sd"):
            if rec.get(k):
                attrs["structured_data" if k == "sd" else "message_identifier"] = rec[k]
        dtype = "syslog:line"
        user = None
        if rec.get("comment"):
            dtype = "syslog:comment"
        elif reporter == "sshd":
            stripped = body.strip()
            for dt_name, rx in SSH_PATTERNS:
                sm = rx.match(stripped)
                if sm:
                    dtype = dt_name
                    for k, v in sm.groupdict().items():
                        if v is not None:
                            attrs[k] = int(v) if k == "port" else v
                    user = attrs.get("username")
                    break
        elif reporter.upper() in ("CRON", "CROND"):
            cm = CRON_RUN.match(body.strip())
            if cm:
                dtype = "syslog:cron:task_run"
                attrs["username"], attrs["command"] = cm.group("username"), cm.group("command")
                user = attrs["username"]
        elif reporter == "sudo":
            sm = SUDO.match(body)
            fields = _sudo_fields(sm.group("fields")) if sm else None
            if sm and fields:
                dtype = "syslog:sudo:command"
                attrs.update({"user": sm.group("user"), "command": fields.get("command"), "tty": fields.get("tty"),
                              "pwd": fields.get("pwd"), "target_user": fields.get("user"), "error": fields.get("error")})
                user = sm.group("user")
        msg = f"[{reporter}{', pid: ' + str(rec['pid']) if rec.get('pid') is not None else ''}] {body}" if reporter else body
        return self.event(dtype, Desc.MODIFICATION, msg, rec.get("ts"), offset=rec["lineno"], attrs=attrs,
                          host=rec.get("host"), user=user)


def _looks_like_syslog(line: str) -> bool:
    if RFC5424.match(line):
        return True
    m = ISO.match(line)
    if m:
        return HOST_REST.match(" " + m.group("rest")) is not None
    m = BSD.match(line)
    if m:
        hm = HOST_REST.match(m.group("rest"))
        return COMMENT.match(m.group("rest")) is not None or (hm is not None and REPORTER.match(hm.group("body")) is not None)
    return False


def _nil(v: str | None) -> str | None:
    return None if v in (None, "-") else v


def _int(v: str | None) -> int | None:
    return int(v) if v and v.isdigit() else None


def _split_body(body: str) -> dict[str, Any]:
    rm = REPORTER.match(body)
    if rm:
        return {"reporter": rm.group("rep"), "pid": _int(rm.group("pid")), "level": rm.group("level"),
                "body": rm.group("msg")}
    return {"reporter": None, "pid": None, "level": None, "body": body}


def _with_pri(rec: dict[str, Any], pri: str | None) -> dict[str, Any]:
    if pri is not None:
        p = int(pri)
        rec["severity"], rec["facility"] = p & 7, p >> 3
    return rec


PARSERS = [SyslogParser]
