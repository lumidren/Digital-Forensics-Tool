"""STIX 2.1 export of case IOCs, and CSV/JSONL/Plaso-style timeline exports.

Identifiers are UUIDv5 derived from the indicator value and case id, and timestamps come from the
IOC records, so exports are deterministic.
"""
from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from ..timeline.schema import Event, format_ns

NS_VERITAS = uuid.UUID("7c0b1b8e-3f0e-5d5e-9a3e-2b9f4c8a1d10")

PATTERNS = {
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "sha1": "[file:hashes.'SHA-1' = '{v}']",
    "md5": "[file:hashes.MD5 = '{v}']",
    "ipv4": "[ipv4-addr:value = '{v}']",
    "ipv6": "[ipv6-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "email": "[email-addr:value = '{v}']",
    "filename": "[file:name = '{v}']",
    "path": "[file:parent_directory_ref.path = '{v}']",
}


def _ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _q(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def stix_bundle(case_id: str, case_name: str, iocs: list[dict[str, Any]], created_by: str) -> dict[str, Any]:
    ident_id = f"identity--{uuid.uuid5(NS_VERITAS, 'identity:' + created_by)}"
    earliest = min((i["created"] for i in iocs), default=datetime(1970, 1, 1, tzinfo=timezone.utc))
    objects: list[dict[str, Any]] = [{
        "type": "identity", "spec_version": "2.1", "id": ident_id, "created": _ts(earliest), "modified": _ts(earliest),
        "name": created_by, "identity_class": "individual",
    }]
    ind_ids = []
    for i in sorted(iocs, key=lambda x: (x["ioc_type"], x["value"])):
        pat = PATTERNS.get(i["ioc_type"])
        if pat is None:
            continue
        sid = f"indicator--{uuid.uuid5(NS_VERITAS, f'{case_id}:{i['ioc_type']}:{i['value']}')}"
        ind_ids.append(sid)
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": sid, "created": _ts(i["created"]), "modified": _ts(i["created"]),
            "created_by_ref": ident_id, "name": f"{i['ioc_type']}: {i['value']}", "pattern": pat.format(v=_q(i["value"])), "pattern_type": "stix",
            "valid_from": _ts(i["created"]), "labels": sorted(i.get("tags") or []) or ["malicious-activity"],
            "description": f"Source: {i.get('source', 'manual')}; hits in case: {i.get('hits', 0)}",
        })
    if ind_ids:
        objects.append({
            "type": "report", "spec_version": "2.1", "id": f"report--{uuid.uuid5(NS_VERITAS, 'report:' + case_id)}", "created": _ts(earliest), "modified": _ts(earliest),
            "created_by_ref": ident_id, "name": f"IOCs for case {case_name} ({case_id})", "published": _ts(earliest), "report_types": ["threat-report"], "object_refs": ind_ids,
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid5(NS_VERITAS, 'bundle:' + case_id + ':' + str(len(ind_ids)))}", "objects": objects}


CSV_FIELDS = ["datetime", "timestamp_desc", "data_type", "source_short", "source_long", "message", "host", "user", "evidence_sha256", "evidence_path", "offset", "parser", "parser_version", "skew_ns", "attrs"]


def timeline_csv(events: Iterable[Event]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_FIELDS)
    for e in events:
        w.writerow([format_ns(e.timestamp) if e.timestamp is not None else "", e.timestamp_desc, e.data_type, e.source_short, e.source_long, e.message, e.host or "", e.user or "",
                    e.evidence_sha256, e.evidence_path, e.offset, e.parser, e.parser_version, e.skew_ns, json.dumps(e.attrs, sort_keys=True, ensure_ascii=False)])
    return buf.getvalue()


def timeline_plaso_json_line(e: Event) -> str:
    """psort ``json_line`` output shape: Plaso field names, microsecond timestamps."""
    d: dict[str, Any] = {
        "__container_type__": "event", "__type__": "AttributeContainer",
        "timestamp": (e.timestamp // 1000) if e.timestamp is not None else 0, "timestamp_desc": e.timestamp_desc, "data_type": e.data_type,
        "message": e.message, "source_short": e.source_short, "source_long": e.source_long, "hostname": e.host, "username": e.user,
        "display_name": e.evidence_path, "parser": e.parser, "sha256_hash": e.evidence_sha256, "offset": e.offset,
    }
    for k, v in sorted(e.attrs.items()):
        if k not in d:
            d[k] = v
    return json.dumps(d, sort_keys=True, ensure_ascii=False)
