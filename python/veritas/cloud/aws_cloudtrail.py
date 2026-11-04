"""AWS CloudTrail normalizer: ``aws:cloudtrail:entry``.

Accepts the ``{"Records": [...]}`` export, a bare JSON array, or JSON Lines; gzip is transparent.
"""
from __future__ import annotations

from typing import Any

from veritas.timeline.schema import Desc

from .base import (
    ParseResult,
    ParserError,
    bounded_json,
    first,
    guard,
    iter_json_records,
    load_bytes,
    make_event,
    parse_time,
    source_name,
    tz_of,
)

DATA_TYPE = "aws:cloudtrail:entry"
PARSER = "aws_cloudtrail"
SOURCE_SHORT = "AWS"
SOURCE_LONG = "AWS CloudTrail"

_IDENTITY_KEYS = ("type", "arn", "userName", "accessKeyId", "accountId", "principalId", "invokedBy")


def looks_like(record: dict) -> bool:
    return isinstance(record, dict) and "eventName" in record and ("eventSource" in record or "eventVersion" in record)


def _identity(record: dict) -> dict[str, Any]:
    ident = record.get("userIdentity")
    out: dict[str, Any] = {}
    if not isinstance(ident, dict):
        return out
    for k in _IDENTITY_KEYS:
        if ident.get(k) not in (None, ""):
            out["identity_" + _snake(k)] = ident[k]
    ctx = ident.get("sessionContext")
    if isinstance(ctx, dict):
        issuer = ctx.get("sessionIssuer")
        if isinstance(issuer, dict):
            for k in ("type", "arn", "userName", "accountId"):
                if issuer.get(k) not in (None, ""):
                    out["session_issuer_" + _snake(k)] = issuer[k]
        attrs = ctx.get("attributes")
        if isinstance(attrs, dict):
            if attrs.get("mfaAuthenticated") is not None:
                out["session_mfa_authenticated"] = str(attrs["mfaAuthenticated"]).lower() == "true"
            if attrs.get("creationDate"):
                out["session_creation_date"] = attrs["creationDate"]
    return out


def _snake(name: str) -> str:
    out = []
    for ch in name:
        if ch.isupper():
            out.append("_" + ch.lower())
        else:
            out.append(ch)
    return "".join(out).lstrip("_")


def _record_to_event(record: dict, index: int, evidence_path: str, evidence_sha256: str, result: ParseResult):
    raw_time = record.get("eventTime")
    ts = parse_time(raw_time)
    if ts is None:
        result.warn(f"record {index}: missing or invalid eventTime {raw_time!r}")
    ident = record.get("userIdentity") if isinstance(record.get("userIdentity"), dict) else {}
    user = first(ident, "arn", "userName", "principalId")
    event_name = record.get("eventName") or "?"
    event_source = record.get("eventSource") or "?"
    attrs: dict[str, Any] = {
        "raw_time": raw_time,
        "event_source": event_source,
        "event_name": event_name,
        "event_version": record.get("eventVersion"),
        "event_id": record.get("eventID"),
        "event_type": record.get("eventType"),
        "event_category": record.get("eventCategory"),
        "aws_region": record.get("awsRegion"),
        "source_ip_address": record.get("sourceIPAddress"),
        "user_agent": record.get("userAgent"),
        "error_code": record.get("errorCode"),
        "error_message": record.get("errorMessage"),
        "read_only": record.get("readOnly"),
        "management_event": record.get("managementEvent"),
        "recipient_account_id": record.get("recipientAccountId"),
        "request_id": record.get("requestID"),
        "shared_event_id": record.get("sharedEventID"),
        "vpc_endpoint_id": record.get("vpcEndpointId"),
        "tls_details": record.get("tlsDetails"),
    }
    attrs.update(_identity(record))
    for key, name in (("requestParameters", "request_parameters"), ("responseElements", "response_elements")):
        val, truncated = bounded_json(record.get(key))
        if val is not None:
            attrs[name] = val
        if truncated:
            attrs[name + "_truncated"] = True
    resources = record.get("resources")
    if isinstance(resources, list) and resources:
        attrs["resources"] = [
            {k: v for k, v in r.items() if k in ("ARN", "accountId", "type")} if isinstance(r, dict) else r
            for r in resources[:64]
        ]
    outcome = f" error={record['errorCode']}" if record.get("errorCode") else ""
    msg = f"{event_source} {event_name} by {user or 'unknown'} from {record.get('sourceIPAddress') or '?'}{outcome}"
    return make_event(
        data_type=DATA_TYPE,
        timestamp_desc=Desc.EVENT,
        message=msg,
        timestamp=ts,
        source_short=SOURCE_SHORT,
        source_long=SOURCE_LONG,
        parser=PARSER,
        evidence_path=evidence_path,
        evidence_sha256=evidence_sha256,
        offset=index,
        user=user,
        timezone=tz_of(raw_time),
        attrs=attrs,
    )


def parse(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    evidence_path = evidence_path or source_name(source)
    result = ParseResult()
    with guard("cloudtrail"):
        data = load_bytes(source)
        n = 0
        for index, record in enumerate(iter_json_records(data)):
            n += 1
            if not looks_like(record):
                result.warn(f"record {index}: not a CloudTrail record (keys={sorted(record)[:6]})")
                continue
            result.events.append(_record_to_event(record, index, evidence_path, evidence_sha256, result))
        if n and not result.events:
            raise ParserError("no CloudTrail records found")
    return result
