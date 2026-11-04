"""AWS S3 server access log normalizer: ``aws:s3:access_log``.

Space-delimited, quoted request/referrer/user-agent fields, ``[dd/Mon/yyyy:HH:MM:SS +0000]`` time.
Newer fields (host id, signature version, TLS version, access point ARN, aclRequired) are optional.
"""
from __future__ import annotations

import re
from typing import Any

from veritas.timeline.schema import Desc

from .base import (
    ParseResult,
    ParserError,
    as_int,
    clf_to_iso,
    dash_none,
    decode_text,
    guard,
    iter_lines,
    load_bytes,
    make_event,
    parse_time,
    source_name,
    split_log_fields,
    tz_of,
)

DATA_TYPE = "aws:s3:access_log"
PARSER = "aws_s3_access"
SOURCE_SHORT = "AWS"
SOURCE_LONG = "AWS S3 server access log"

FIELDS = (
    "bucket_owner", "bucket", "time", "remote_ip", "requester", "request_id", "operation", "key",
    "request_uri", "http_status", "error_code", "bytes_sent", "object_size", "total_time",
    "turn_around_time", "referrer", "user_agent", "version_id", "host_id", "signature_version",
    "cipher_suite", "authentication_type", "host_header", "tls_version", "access_point_arn",
    "acl_required",
)
_INT_FIELDS = ("http_status", "bytes_sent", "object_size", "total_time", "turn_around_time")
LINE_RE = re.compile(r"^\S+ \S+ \[\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] ")


def looks_like(line: str) -> bool:
    return bool(LINE_RE.match(line))


def parse_line(line: str) -> dict[str, Any] | None:
    if not looks_like(line):
        return None
    fields = split_log_fields(line)
    if len(fields) < 17:
        return None
    rec: dict[str, Any] = {}
    for name, value in zip(FIELDS, fields):
        rec[name] = value
    if len(fields) > len(FIELDS):
        rec["extra_fields"] = fields[len(FIELDS):]
    return rec


def parse(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    evidence_path = evidence_path or source_name(source)
    result = ParseResult()
    with guard("s3 access log"):
        text = decode_text(load_bytes(source))
        seen = 0
        for lineno, offset, line in iter_lines(text):
            seen += 1
            rec = parse_line(line)
            if rec is None:
                result.warn(f"line {lineno}: not an S3 access log record")
                continue
            raw_time = rec["time"]
            iso = clf_to_iso(raw_time)
            ts = parse_time(iso) if iso else None
            if ts is None:
                result.warn(f"line {lineno}: unparseable time {raw_time!r}")
            attrs: dict[str, Any] = {"raw_time": raw_time}
            for name in FIELDS:
                if name == "time" or name not in rec:
                    continue
                val = dash_none(rec[name])
                if name in _INT_FIELDS:
                    val = as_int(val)
                attrs[name] = val
            if "extra_fields" in rec:
                attrs["extra_fields"] = rec["extra_fields"]
            req = rec.get("request_uri") or "-"
            parts = req.split(" ")
            if len(parts) >= 2 and parts[0] != "-":
                attrs["http_method"] = parts[0]
                attrs["request_path"] = parts[1]
            requester = dash_none(rec.get("requester"))
            msg = (
                f"{rec['operation']} {rec['bucket']}/{rec['key'] if rec['key'] != '-' else ''} "
                f"status={rec['http_status']} from {rec['remote_ip']} requester={requester or 'anonymous'}"
            )
            result.events.append(
                make_event(
                    data_type=DATA_TYPE,
                    timestamp_desc=Desc.EVENT,
                    message=msg,
                    timestamp=ts,
                    source_short=SOURCE_SHORT,
                    source_long=SOURCE_LONG,
                    parser=PARSER,
                    evidence_path=evidence_path,
                    evidence_sha256=evidence_sha256,
                    offset=offset,
                    user=requester,
                    timezone=tz_of(iso) if iso else None,
                    attrs=attrs,
                )
            )
        if seen and not result.events:
            raise ParserError("no S3 access log records found")
        if not seen:
            raise ParserError("empty file")
    return result
