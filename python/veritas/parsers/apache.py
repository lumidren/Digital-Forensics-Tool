"""Apache / nginx access logs in Common and Combined Log Format (with optional vhost prefix).

``host ident user [dd/Mon/yyyy:HH:MM:SS +zzzz] "METHOD path PROTO" status bytes ["referer" "agent"]``
-> ``apache:access_log:entry`` (Recorded Time). The ``+zzzz`` offset is applied so timestamps are
UTC; the original offset is kept in ``attrs.utc_offset``.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterator

from veritas.parsers.text_log import TextLogParser
from veritas.timeline.schema import NS, Event

LINE = re.compile(
    r'^(?:(?P<vhost>[^\s:]+:\d+)\s+)?(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>.+?)\s+\[(?P<ts>[^\]]+)\]\s+'
    # Lazy request match: requests may contain raw quotes (injection attempts); the request ends at
    # the first `" <status> <size>` sequence.
    r'"(?P<request>.*?)"\s+(?P<status>\d{3}|-)\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>(?:[^"\\]|\\.)*)"\s+"(?P<agent>(?:[^"\\]|\\.)*)")?(?P<extra>.*)$')
RECORDED = "Recorded Time"


class ApacheAccessParser(TextLogParser):
    name = "apache_access"
    version = "1.0"
    source_short = "LOG"
    source_long = "Apache Access Log"
    head_regex = re.compile(r'^\S+ \S+ .+? \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "', re.M)

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        if not line.strip():
            return
        m = LINE.match(line)
        if not m:
            self.warn(f"line {lineno}: not an access log line")
            return
        try:
            dt = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            self.warn(f"line {lineno}: bad timestamp")
            return
        req = m.group("request")
        parts = req.split(" ")
        nil = (lambda v: None if v in (None, "-") else v)
        attrs = {
            "ip_address": m.group("ip"), "remote_name": nil(m.group("ident")), "user_name": nil(m.group("user")),
            "http_request": req, "http_method": parts[0] if len(parts) >= 2 else None,
            "path": parts[1] if len(parts) >= 2 else None, "protocol": parts[2] if len(parts) >= 3 else None,
            "http_response_code": int(m.group("status")) if m.group("status").isdigit() else None,
            "http_response_bytes": int(m.group("size")) if m.group("size").isdigit() else None,
            "http_request_referer": nil(m.group("referer")), "http_request_user_agent": nil(m.group("agent")),
            "server_name": m.group("vhost"), "utc_offset": dt.strftime("%z"),
        }
        msg = f"{attrs['ip_address']} {req} {m.group('status')} {m.group('size')}"
        yield self.event("apache:access_log:entry", RECORDED, msg, int(dt.timestamp()) * NS, offset=lineno, attrs=attrs,
                         user=attrs["user_name"])


PARSERS = [ApacheAccessParser]
