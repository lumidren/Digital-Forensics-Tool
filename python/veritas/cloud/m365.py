"""Microsoft 365 Unified Audit Log: ``m365:ual:entry``.

Inputs:

* Purview "Export results" CSV (columns ``RecordId, CreationDate, RecordType, Operation, UserId,
  AuditData, ...`` or the older ``CreationDate, UserIds, Operations, AuditData``) where
  ``AuditData`` holds the full JSON record;
* the raw JSON array of AuditData records (``Search-UnifiedAuditLog | ConvertTo-Json`` of
  AuditData, or the Management Activity API content blob), or JSON Lines.
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from veritas.timeline.schema import Desc

from .base import (
    ParseResult,
    ParserError,
    as_int,
    decode_text,
    first,
    guard,
    iter_json_records,
    load_bytes,
    make_event,
    parse_time,
    source_name,
    tz_of,
)

DATA_TYPE = "m365:ual:entry"
PARSER = "m365_ual"

# https://learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-schema#auditlogrecordtype
RECORD_TYPES: dict[int, str] = {
    1: "ExchangeAdmin",
    2: "ExchangeItem",
    3: "ExchangeItemGroup",
    4: "SharePoint",
    6: "SharePointFileOperation",
    7: "OneDrive",
    8: "AzureActiveDirectory",
    9: "AzureActiveDirectoryAccountLogon",
    10: "DataCenterSecurityCmdlet",
    11: "ComplianceDLPSharePoint",
    13: "ComplianceDLPExchange",
    14: "SharePointSharingOperation",
    15: "AzureActiveDirectoryStsLogon",
    16: "SkypeForBusinessPSTNUsage",
    18: "SecurityComplianceCenterEOPCmdlet",
    20: "PowerBIAudit",
    22: "Yammer",
    23: "SkypeForBusinessCmdlets",
    24: "Discovery",
    25: "MicrosoftTeams",
    28: "ThreatIntelligence",
    29: "MailSubmission",
    30: "MicrosoftFlow",
    32: "MicrosoftStream",
    35: "Project",
    36: "SharePointListOperation",
    40: "SecurityComplianceAlerts",
    41: "ThreatIntelligenceUrl",
    45: "PowerAppsApp",
    47: "ThreatIntelligenceAtpContent",
    50: "ExchangeItemAggregated",
    54: "SharePointListItemOperation",
    64: "AirInvestigation",
    78: "HygieneEvent",
}

_US_DATE_RE = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4}) (\d{1,2}):(\d{2})(?::(\d{2}))?(?: ?([AaPp][Mm]))?$")
_SIGNIN_OPS = {"UserLoggedIn", "UserLoginFailed"}


def record_type_name(value: Any) -> str | None:
    n = as_int(value)
    if n is not None:
        return RECORD_TYPES.get(n, f"Unknown({n})")
    if isinstance(value, str) and value:
        return value
    return None


def looks_like(rec: dict) -> bool:
    return isinstance(rec, dict) and "CreationTime" in rec and "Operation" in rec and (
        "RecordType" in rec or "Workload" in rec
    )


def _us_date(text: str) -> str | None:
    m = _US_DATE_RE.match(text.strip())
    if not m:
        return None
    mo, d, y, hh, mi, ss, ampm = m.groups()
    h = int(hh)
    if ampm:
        h = h % 12 + (12 if ampm.lower() == "pm" else 0)
    return f"{int(y):04d}-{int(mo):02d}-{int(d):02d}T{h:02d}:{mi}:{ss or '00'}+00:00"


def _time(raw: Any) -> int | None:
    ts = parse_time(raw)
    if ts is None and isinstance(raw, str):
        iso = _us_date(raw)
        if iso:
            ts = parse_time(iso)
    return ts


def _workload_specifics(rec: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    # Exchange mailbox auditing
    for k, name in (("MailboxOwnerUPN", "mailbox_owner_upn"), ("LogonType", "logon_type"),
                    ("ClientInfoString", "client_info_string"), ("ExternalAccess", "external_access"),
                    ("InternalLogonType", "internal_logon_type"), ("MailboxGuid", "mailbox_guid")):
        if k in rec:
            out[name] = rec[k]
    folders = rec.get("Folders")
    if isinstance(folders, list):
        paths = []
        subjects = []
        for f in folders[:64]:
            if isinstance(f, dict):
                if f.get("Path"):
                    paths.append(f["Path"])
                for item in f.get("FolderItems") or []:
                    if isinstance(item, dict) and item.get("Subject"):
                        subjects.append(item["Subject"])
        out["folders"] = paths
        if subjects:
            out["item_subjects"] = subjects[:64]
    item = rec.get("Item")
    if isinstance(item, dict):
        out["item_subject"] = item.get("Subject")
        out["item_id"] = item.get("Id")
        if isinstance(item.get("ParentFolder"), dict):
            out["item_parent_folder"] = item["ParentFolder"].get("Path")
    if isinstance(rec.get("AffectedItems"), list):
        out["affected_item_subjects"] = [a.get("Subject") for a in rec["AffectedItems"][:64] if isinstance(a, dict)]
    if "Parameters" in rec and isinstance(rec["Parameters"], list):
        out["parameters"] = {
            str(p.get("Name")): p.get("Value") for p in rec["Parameters"][:128] if isinstance(p, dict) and p.get("Name")
        }
    # SharePoint / OneDrive
    for k, name in (("SourceFileName", "source_file_name"), ("SourceFileExtension", "source_file_extension"),
                    ("SourceRelativeUrl", "source_relative_url"), ("SiteUrl", "site_url"), ("Site", "site_id"),
                    ("ItemType", "item_type"), ("UserAgent", "user_agent"), ("EventSource", "event_source"),
                    ("DestinationFileName", "destination_file_name"), ("TargetUserOrGroupName", "target_user_or_group")):
        if k in rec:
            out[name] = rec[k]
    # Azure AD
    for k, name in (("ExtendedProperties", "extended_properties"), ("ModifiedProperties", "modified_properties"),
                    ("Actor", "actor"), ("Target", "target"), ("DeviceProperties", "device_properties")):
        val = rec.get(k)
        if isinstance(val, list):
            if k in ("Actor", "Target"):
                out[name] = [v.get("ID") for v in val[:32] if isinstance(v, dict)]
            elif k == "ModifiedProperties":
                out[name] = [
                    {"name": v.get("Name"), "old": v.get("OldValue"), "new": v.get("NewValue")}
                    for v in val[:64] if isinstance(v, dict)
                ]
            else:
                out[name] = {str(v.get("Name")): v.get("Value") for v in val[:64] if isinstance(v, dict) and v.get("Name")}
    for k, name in (("LogonError", "logon_error"), ("ErrorNumber", "error_number"),
                    ("ApplicationId", "application_id"), ("AzureActiveDirectoryEventType", "aad_event_type"),
                    ("ActorIpAddress", "actor_ip_address"), ("InterSystemsId", "inter_systems_id")):
        if k in rec:
            out[name] = rec[k]
    return out


def _record_event(rec: dict, index: int, ev_path: str, ev_sha: str, result: ParseResult, csv_row: dict | None):
    raw_time = rec.get("CreationTime") or (csv_row or {}).get("CreationDate")
    ts = _time(raw_time)
    if ts is None:
        result.warn(f"record {index}: invalid CreationTime {raw_time!r}")
    operation = rec.get("Operation") or (csv_row or {}).get("Operation") or (csv_row or {}).get("Operations")
    user = rec.get("UserId") or (csv_row or {}).get("UserId") or (csv_row or {}).get("UserIds")
    rtype_raw = rec.get("RecordType", (csv_row or {}).get("RecordType"))
    client_ip = first(rec, "ClientIP", "ClientIPAddress", "ActorIpAddress")
    attrs: dict[str, Any] = {
        "raw_time": raw_time,
        "id": rec.get("Id"),
        "operation": operation,
        "record_type": as_int(rtype_raw) if as_int(rtype_raw) is not None else rtype_raw,
        "record_type_name": record_type_name(rtype_raw),
        "user_id": user,
        "user_type": rec.get("UserType"),
        "user_key": rec.get("UserKey"),
        "organization_id": rec.get("OrganizationId"),
        "client_ip": client_ip,
        "workload": rec.get("Workload"),
        "object_id": rec.get("ObjectId"),
        "result_status": rec.get("ResultStatus"),
    }
    attrs.update(_workload_specifics(rec))
    if operation in _SIGNIN_OPS:
        attrs["login_success"] = operation == "UserLoggedIn"
    if csv_row is not None and csv_row.get("RecordId"):
        attrs["csv_record_id"] = csv_row["RecordId"]
    desc = Desc.LAST_LOGIN if operation in _SIGNIN_OPS else Desc.EVENT
    msg = (
        f"{rec.get('Workload') or attrs['record_type_name'] or '?'}: {operation or '?'} by {user or 'unknown'}"
        f" from {client_ip or '?'}"
        + (f" [{rec['ResultStatus']}]" if rec.get("ResultStatus") else "")
        + (f" object={rec['ObjectId']}" if rec.get("ObjectId") else "")
    )
    return make_event(
        data_type=DATA_TYPE, timestamp_desc=desc, message=msg, timestamp=ts,
        source_short="M365", source_long="Microsoft 365 unified audit log", parser=PARSER,
        evidence_path=ev_path, evidence_sha256=ev_sha, offset=index, user=user,
        timezone=tz_of(raw_time) or ("UTC" if ts is not None else None), attrs=attrs,
    )


def _is_csv(text: str) -> bool:
    head = text.lstrip()[:4096]
    if head.startswith(("[", "{")):
        return False
    first_line = head.splitlines()[0] if head else ""
    return "AuditData" in first_line and "," in first_line


def parse(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    evidence_path = evidence_path or source_name(source)
    result = ParseResult()
    with guard("m365 unified audit log"):
        data = load_bytes(source)
        text = decode_text(data)
        if _is_csv(text):
            csv.field_size_limit(16 * 1024 * 1024)
            reader = csv.DictReader(io.StringIO(text, newline=""))
            for index, row in enumerate(reader):
                raw = row.get("AuditData")
                try:
                    rec = json.loads(raw) if raw else None
                except (json.JSONDecodeError, RecursionError):
                    rec = None
                if not isinstance(rec, dict):
                    result.warn(f"row {index}: AuditData is not a JSON object")
                    continue
                result.events.append(_record_event(rec, index, evidence_path, evidence_sha256, result, row))
        else:
            for index, rec in enumerate(iter_json_records(data, wrappers=("value", "Records", "records"))):
                if isinstance(rec.get("AuditData"), (str, dict)) and "CreationTime" not in rec:
                    inner = rec["AuditData"]
                    if isinstance(inner, str):
                        try:
                            inner = json.loads(inner)
                        except (json.JSONDecodeError, RecursionError):
                            inner = None
                    if isinstance(inner, dict):
                        result.events.append(_record_event(inner, index, evidence_path, evidence_sha256, result, rec))
                        continue
                if not looks_like(rec):
                    result.warn(f"record {index}: not a unified audit log record")
                    continue
                result.events.append(_record_event(rec, index, evidence_path, evidence_sha256, result, None))
        if not result.events:
            raise ParserError("no unified audit log records found")
    return result


__all__ = ["DATA_TYPE", "RECORD_TYPES", "parse", "record_type_name", "looks_like"]
