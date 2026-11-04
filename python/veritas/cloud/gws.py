"""Google Workspace Reports API activities: ``gws:audit:entry``.

Input: the ``{"kind": "admin#reports#activities", "items": [...]}`` response, a bare array of
activities, or JSON Lines. One event is emitted per ``events[]`` element of an activity, with the
event parameters flattened as ``param_<name>``.
"""
from __future__ import annotations

import re
from typing import Any

from veritas.timeline.schema import Desc

from .base import (
    ParseResult,
    ParserError,
    guard,
    iter_json_records,
    load_bytes,
    make_event,
    parse_time,
    source_name,
    tz_of,
)

DATA_TYPE = "gws:audit:entry"
PARSER = "gws_reports"
_PARAM_NAME_RE = re.compile(r"[^A-Za-z0-9_]+")
_VALUE_KEYS = ("value", "intValue", "boolValue", "multiValue", "multiIntValue", "messageValue", "multiMessageValue")


def looks_like(rec: dict) -> bool:
    ident = rec.get("id") if isinstance(rec, dict) else None
    return isinstance(ident, dict) and "time" in ident and "applicationName" in ident


def _param_value(p: dict) -> Any:
    for key in _VALUE_KEYS:
        if key in p:
            val = p[key]
            if key == "intValue" and isinstance(val, str) and val.lstrip("-").isdigit():
                return int(val)
            if key == "multiIntValue" and isinstance(val, list):
                return [int(v) if isinstance(v, str) and v.lstrip("-").isdigit() else v for v in val]
            if key == "messageValue" and isinstance(val, dict):
                return _flatten_params(val.get("parameter") or [])
            if key == "multiMessageValue" and isinstance(val, list):
                return [_flatten_params(m.get("parameter") or []) for m in val if isinstance(m, dict)]
            return val
    return None


def _flatten_params(params: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(params, list):
        return out
    for p in params:
        if isinstance(p, dict) and p.get("name"):
            out[str(p["name"])] = _param_value(p)
    return out


def parse(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    evidence_path = evidence_path or source_name(source)
    result = ParseResult()
    with guard("google workspace reports"):
        data = load_bytes(source)
        index = -1
        for rec_no, rec in enumerate(iter_json_records(data, wrappers=("items",))):
            if not looks_like(rec):
                result.warn(f"activity {rec_no}: not a Reports API activity")
                continue
            ident = rec["id"]
            raw_time = ident.get("time")
            ts = parse_time(raw_time)
            if ts is None:
                result.warn(f"activity {rec_no}: invalid id.time {raw_time!r}")
            actor = rec.get("actor") if isinstance(rec.get("actor"), dict) else {}
            email = actor.get("email")
            app = ident.get("applicationName")
            events = rec.get("events") if isinstance(rec.get("events"), list) else []
            if not events:
                events = [{}]
            for sub_no, ev in enumerate(events):
                index += 1
                ev = ev if isinstance(ev, dict) else {}
                attrs: dict[str, Any] = {
                    "raw_time": raw_time,
                    "application_name": app,
                    "unique_qualifier": ident.get("uniqueQualifier"),
                    "customer_id": ident.get("customerId"),
                    "actor_email": email,
                    "actor_profile_id": actor.get("profileId"),
                    "actor_caller_type": actor.get("callerType"),
                    "actor_key": actor.get("key"),
                    "ip_address": rec.get("ipAddress"),
                    "owner_domain": rec.get("ownerDomain"),
                    "etag": rec.get("etag"),
                    "event_name": ev.get("name"),
                    "event_type": ev.get("type"),
                    "event_index": sub_no,
                }
                for name, value in _flatten_params(ev.get("parameters")).items():
                    attrs["param_" + _PARAM_NAME_RE.sub("_", name)] = value
                msg = f"{app}: {ev.get('name') or '?'} ({ev.get('type') or '-'}) by {email or 'unknown'} from {rec.get('ipAddress') or '?'}"
                result.events.append(
                    make_event(
                        data_type=DATA_TYPE, timestamp_desc=Desc.EVENT, message=msg, timestamp=ts,
                        source_short="GWS", source_long=f"Google Workspace {app} audit", parser=PARSER,
                        evidence_path=evidence_path, evidence_sha256=evidence_sha256, offset=index,
                        user=email, timezone=tz_of(raw_time), attrs=attrs,
                    )
                )
        if not result.events:
            raise ParserError("no Google Workspace activities found")
    return result
