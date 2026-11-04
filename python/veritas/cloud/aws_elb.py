"""AWS Elastic Load Balancing access logs: ``aws:elb:access``.

Supports the three layouts found in the reference corpus:

* Application Load Balancer (``type time elb client:port target:port ...``),
* Classic Load Balancer (``time elb client:port backend:port ...``),
* Network Load Balancer TLS listener (``tls version time elb listener ...``).
"""
from __future__ import annotations

import re
from typing import Any

from veritas.timeline.schema import Desc

from .base import (
    ParseResult,
    ParserError,
    as_int,
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

DATA_TYPE = "aws:elb:access"
PARSER = "aws_elb_access"
SOURCE_SHORT = "AWS"
SOURCE_LONG = "AWS ELB access log"

ALB_FIELDS = (
    "type", "time", "elb", "client", "target", "request_processing_time", "target_processing_time",
    "response_processing_time", "elb_status_code", "target_status_code", "received_bytes", "sent_bytes",
    "request", "user_agent", "ssl_cipher", "ssl_protocol", "target_group_arn", "trace_id", "domain_name",
    "chosen_cert_arn", "matched_rule_priority", "request_creation_time", "actions_executed", "redirect_url",
    "error_reason", "target_port_list", "target_status_code_list", "classification", "classification_reason",
    "conn_trace_id",
)
CLASSIC_FIELDS = (
    "time", "elb", "client", "target", "request_processing_time", "target_processing_time",
    "response_processing_time", "elb_status_code", "target_status_code", "received_bytes", "sent_bytes",
    "request", "user_agent", "ssl_cipher", "ssl_protocol",
)
NLB_FIELDS = (
    "type", "version", "time", "elb", "listener", "client", "target", "connection_time", "tls_handshake_time",
    "received_bytes", "sent_bytes", "incoming_tls_alert", "chosen_cert_arn", "chosen_cert_serial", "tls_cipher",
    "tls_protocol_version", "tls_named_group", "domain_name", "alpn_fe_protocol", "alpn_be_protocol",
    "alpn_client_preference_list", "tls_connection_creation_time",
)
_INT_FIELDS = {
    "elb_status_code", "target_status_code", "received_bytes", "sent_bytes", "matched_rule_priority",
    "connection_time", "tls_handshake_time",
}
_ALB_TYPES = {"http", "https", "h2", "grpcs", "ws", "wss"}
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def classify(line: str) -> str | None:
    tokens = line.split(" ", 3)
    if len(tokens) < 3:
        return None
    if tokens[0] in _ALB_TYPES and _ISO_RE.match(tokens[1]):
        return "alb"
    if tokens[0] == "tls" and _ISO_RE.match(tokens[2]):
        return "nlb"
    if _ISO_RE.match(tokens[0]) and not tokens[1].startswith(("app/", "net/")):
        return "classic"
    return None


def looks_like(line: str) -> bool:
    return classify(line) is not None


def parse_line(line: str) -> tuple[str, dict[str, Any]] | None:
    kind = classify(line)
    if kind is None:
        return None
    layout = {"alb": ALB_FIELDS, "classic": CLASSIC_FIELDS, "nlb": NLB_FIELDS}[kind]
    fields = split_log_fields(line)
    minimum = {"alb": 12, "classic": 11, "nlb": 11}[kind]
    if len(fields) < minimum:
        return None
    rec = dict(zip(layout, fields))
    if len(fields) > len(layout):
        rec["extra_fields"] = fields[len(layout):]
    return kind, rec


def _split_hostport(value: str | None) -> tuple[str | None, int | None]:
    value = dash_none(value)
    if not value:
        return None, None
    if ":" in value:
        host, _, port = value.rpartition(":")
        return host, as_int(port)
    return value, None


def parse(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    evidence_path = evidence_path or source_name(source)
    result = ParseResult()
    with guard("elb access log"):
        text = decode_text(load_bytes(source))
        seen = 0
        for lineno, offset, line in iter_lines(text):
            seen += 1
            parsed = parse_line(line)
            if parsed is None:
                result.warn(f"line {lineno}: not an ELB access log record")
                continue
            kind, rec = parsed
            raw_time = rec["time"]
            ts = parse_time(raw_time)
            if ts is None:
                result.warn(f"line {lineno}: unparseable time {raw_time!r}")
            attrs: dict[str, Any] = {"raw_time": raw_time, "log_format": kind}
            for name, value in rec.items():
                if name in ("time", "client", "target"):
                    continue
                val = dash_none(value)
                if name in _INT_FIELDS:
                    val = as_int(val)
                attrs[name] = val
            client_ip, client_port = _split_hostport(rec.get("client"))
            target_ip, target_port = _split_hostport(rec.get("target"))
            attrs["client_ip"], attrs["client_port"] = client_ip, client_port
            attrs["target_ip"], attrs["target_port"] = target_ip, target_port
            req = rec.get("request")
            if req and req.strip("- ") != "":
                parts = req.split(" ")
                if len(parts) >= 2:
                    attrs["http_method"] = parts[0]
                    attrs["request_url"] = parts[1]
                if len(parts) >= 3:
                    attrs["http_version"] = parts[2]
            elb = rec.get("elb")
            if kind == "nlb":
                msg = f"TLS connection {client_ip} -> {target_ip} on {elb} cipher={rec.get('tls_cipher')}"
                desc = Desc.END
            else:
                msg = (
                    f"{attrs.get('http_method') or '-'} {attrs.get('request_url') or '-'} "
                    f"status={rec.get('elb_status_code')} from {client_ip} via {elb}"
                )
                desc = Desc.END
            base = dict(
                data_type=DATA_TYPE,
                source_short=SOURCE_SHORT,
                source_long=SOURCE_LONG,
                parser=PARSER,
                evidence_path=evidence_path,
                evidence_sha256=evidence_sha256,
                offset=offset,
                host=elb,
                attrs=attrs,
            )
            result.events.append(
                make_event(timestamp_desc=desc, message=msg, timestamp=ts, timezone=tz_of(raw_time), **base)
            )
            start_raw = dash_none(rec.get("request_creation_time")) or dash_none(rec.get("tls_connection_creation_time"))
            if start_raw:
                start_ts = parse_time(start_raw)
                if start_ts is not None:
                    result.events.append(
                        make_event(
                            timestamp_desc=Desc.START,
                            message=msg,
                            timestamp=start_ts,
                            timezone=tz_of(start_raw),
                            **base,
                        )
                    )
                else:
                    result.warn(f"line {lineno}: unparseable request creation time {start_raw!r}")
        if not seen:
            raise ParserError("empty file")
        if not result.events:
            raise ParserError("no ELB access log records found")
    return result
