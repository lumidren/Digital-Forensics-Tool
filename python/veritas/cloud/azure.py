"""Azure normalizers.

* ``azure:activity_log:entry``  Azure Monitor activity log export (JSON array / ``value`` / ``records`` / JSON Lines)
* ``azure:entra:audit``         Entra ID (Azure AD) audit log JSON export (Graph ``directoryAudits``)
* ``azure:entra:signin``        Entra ID sign-in log JSON export (Graph ``signIns``)
* ``azure:appgw:access``        Application Gateway access log (diagnostic JSON)
"""
from __future__ import annotations

from typing import Any, Callable

from veritas.timeline.schema import Desc

from .base import (
    ParseResult,
    ParserError,
    as_int,
    bounded_json,
    first,
    fixed6,
    guard,
    iter_json_records,
    load_bytes,
    make_event,
    parse_time,
    source_name,
    tz_of,
)

SOURCE_SHORT = "AZURE"

ACTIVITY = "azure:activity_log:entry"
ENTRA_AUDIT = "azure:entra:audit"
ENTRA_SIGNIN = "azure:entra:signin"
APPGW = "azure:appgw:access"


def _localized(value: Any) -> Any:
    """Activity log fields are often ``{"value": ..., "localizedValue": ...}``."""
    if isinstance(value, dict):
        return value.get("value") or value.get("localizedValue")
    return value


# --------------------------------------------------------------------------- detection


def is_activity(rec: dict) -> bool:
    if not isinstance(rec, dict):
        return False
    has_time = any(k in rec for k in ("time", "eventTimestamp"))
    return has_time and "operationName" in rec and ("resourceId" in rec or "category" in rec) and not is_appgw(rec)


def is_entra_signin(rec: dict) -> bool:
    return isinstance(rec, dict) and "createdDateTime" in rec and (
        "userPrincipalName" in rec or "appDisplayName" in rec or "conditionalAccessStatus" in rec
    )


def is_entra_audit(rec: dict) -> bool:
    return isinstance(rec, dict) and "activityDateTime" in rec and ("activityDisplayName" in rec or "initiatedBy" in rec)


def is_appgw(rec: dict) -> bool:
    return isinstance(rec, dict) and (
        rec.get("category") in ("ApplicationGatewayAccessLog", "ApplicationGatewayFirewallLog")
        or rec.get("operationName") == "ApplicationGatewayAccess"
    )


# --------------------------------------------------------------------------- record converters


def _activity(rec: dict, index: int, ev_path: str, ev_sha: str, result: ParseResult):
    raw_time = first(rec, "time", "eventTimestamp")
    ts = parse_time(raw_time)
    if ts is None:
        result.warn(f"record {index}: invalid time {raw_time!r}")
    identity = rec.get("identity") if isinstance(rec.get("identity"), dict) else {}
    claims = identity.get("claims") if isinstance(identity.get("claims"), dict) else {}
    caller = first(rec, "caller") or first(
        claims,
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "name",
        "appid",
    )
    operation = _localized(rec.get("operationName"))
    result_type = first(rec, "resultType") or _localized(rec.get("status"))
    caller_ip = first(rec, "callerIpAddress") or first(claims, "ipaddr")
    attrs: dict[str, Any] = {
        "raw_time": raw_time,
        "resource_id": rec.get("resourceId"),
        "operation_name": operation,
        "operation_version": rec.get("operationVersion"),
        "category": _localized(rec.get("category")),
        "result_type": result_type,
        "result_signature": rec.get("resultSignature") or _localized(rec.get("subStatus")),
        "result_description": rec.get("resultDescription"),
        "duration_ms": as_int(rec.get("durationMs")),
        "caller_ip_address": caller_ip,
        "correlation_id": rec.get("correlationId"),
        "level": rec.get("level"),
        "location": rec.get("location"),
        "tenant_id": rec.get("tenantId"),
        "subscription_id": rec.get("subscriptionId"),
        "event_data_id": rec.get("eventDataId"),
        "caller": caller,
    }
    if claims:
        keep = {}
        for k in sorted(claims):
            short = k.rsplit("/", 1)[-1]
            if short in ("upn", "name", "appid", "ipaddr", "oid", "tid", "idtyp", "puid", "objectidentifier",
                         "tenantid", "givenname", "surname", "emailaddress", "nameidentifier"):
                keep[short] = claims[k]
        attrs["identity_claims"] = keep
    if isinstance(identity.get("authorization"), dict):
        authz = identity["authorization"]
        attrs["authorization_action"] = authz.get("action")
        attrs["authorization_scope"] = authz.get("scope")
    props, truncated = bounded_json(rec.get("properties"))
    attrs["properties"] = props
    if truncated:
        attrs["properties_truncated"] = True
    msg = f"{operation} [{result_type or '?'}] on {rec.get('resourceId') or '?'} by {caller or 'unknown'}"
    return make_event(
        data_type=ACTIVITY, timestamp_desc=Desc.EVENT, message=msg, timestamp=ts,
        source_short=SOURCE_SHORT, source_long="Azure Monitor activity log", parser="azure_activity",
        evidence_path=ev_path, evidence_sha256=ev_sha, offset=index, user=caller,
        timezone=tz_of(raw_time), attrs=attrs,
    )


def _initiator(initiated: Any) -> tuple[str | None, dict[str, Any]]:
    out: dict[str, Any] = {}
    if not isinstance(initiated, dict):
        return None, out
    user = initiated.get("user") if isinstance(initiated.get("user"), dict) else None
    app = initiated.get("app") if isinstance(initiated.get("app"), dict) else None
    who = None
    if user:
        out["initiated_by_user_upn"] = user.get("userPrincipalName")
        out["initiated_by_user_id"] = user.get("id")
        out["initiated_by_user_display_name"] = user.get("displayName")
        out["initiated_by_ip_address"] = user.get("ipAddress")
        who = user.get("userPrincipalName") or user.get("displayName") or user.get("id")
    if app:
        out["initiated_by_app_display_name"] = app.get("displayName")
        out["initiated_by_app_id"] = app.get("appId")
        out["initiated_by_service_principal_id"] = app.get("servicePrincipalId")
        out["initiated_by_service_principal_name"] = app.get("servicePrincipalName")
        who = who or app.get("displayName") or app.get("servicePrincipalName") or app.get("appId")
    return who, out


def _entra_audit(rec: dict, index: int, ev_path: str, ev_sha: str, result: ParseResult):
    raw_time = rec.get("activityDateTime")
    ts = parse_time(raw_time)
    if ts is None:
        result.warn(f"record {index}: invalid activityDateTime {raw_time!r}")
    who, attrs = _initiator(rec.get("initiatedBy"))
    targets = []
    for t in rec.get("targetResources") or []:
        if not isinstance(t, dict):
            continue
        entry = {
            "id": t.get("id"),
            "display_name": t.get("displayName"),
            "type": t.get("type"),
            "user_principal_name": t.get("userPrincipalName"),
        }
        mods = []
        for m in t.get("modifiedProperties") or []:
            if isinstance(m, dict):
                mods.append({"name": m.get("displayName"), "old": m.get("oldValue"), "new": m.get("newValue")})
        if mods:
            entry["modified_properties"] = mods[:64]
        targets.append({k: v for k, v in entry.items() if v is not None})
    activity = rec.get("activityDisplayName") or "?"
    result_text = rec.get("result")
    attrs.update({
        "raw_time": raw_time,
        "id": rec.get("id"),
        "category": rec.get("category"),
        "correlation_id": rec.get("correlationId"),
        "activity_display_name": activity,
        "operation_type": rec.get("operationType"),
        "logged_by_service": rec.get("loggedByService"),
        "result": result_text,
        "result_reason": rec.get("resultReason"),
        "target_resources": targets[:64],
    })
    details = rec.get("additionalDetails")
    if isinstance(details, list):
        attrs["additional_details"] = {
            str(d.get("key")): d.get("value") for d in details if isinstance(d, dict) and d.get("key") is not None
        }
    target_names = ", ".join(str(t.get("user_principal_name") or t.get("display_name") or t.get("id")) for t in targets[:3])
    msg = f"{activity} [{result_text or '?'}] by {who or 'unknown'}" + (f" on {target_names}" if target_names else "")
    return make_event(
        data_type=ENTRA_AUDIT, timestamp_desc=Desc.EVENT, message=msg, timestamp=ts,
        source_short=SOURCE_SHORT, source_long="Entra ID audit log", parser="azure_entra_audit",
        evidence_path=ev_path, evidence_sha256=ev_sha, offset=index, user=who,
        timezone=tz_of(raw_time), attrs=attrs,
    )


def _entra_signin(rec: dict, index: int, ev_path: str, ev_sha: str, result: ParseResult):
    raw_time = rec.get("createdDateTime")
    ts = parse_time(raw_time)
    if ts is None:
        result.warn(f"record {index}: invalid createdDateTime {raw_time!r}")
    status = rec.get("status") if isinstance(rec.get("status"), dict) else {}
    device = rec.get("deviceDetail") if isinstance(rec.get("deviceDetail"), dict) else {}
    location = rec.get("location") if isinstance(rec.get("location"), dict) else {}
    geo = location.get("geoCoordinates") if isinstance(location.get("geoCoordinates"), dict) else {}
    error_code = as_int(status.get("errorCode"))
    upn = rec.get("userPrincipalName")
    attrs: dict[str, Any] = {
        "raw_time": raw_time,
        "id": rec.get("id"),
        "user_principal_name": upn,
        "user_display_name": rec.get("userDisplayName"),
        "user_id": rec.get("userId"),
        "app_display_name": rec.get("appDisplayName"),
        "app_id": rec.get("appId"),
        "resource_display_name": rec.get("resourceDisplayName"),
        "ip_address": rec.get("ipAddress"),
        "client_app_used": rec.get("clientAppUsed"),
        "correlation_id": rec.get("correlationId"),
        "conditional_access_status": rec.get("conditionalAccessStatus"),
        "is_interactive": rec.get("isInteractive"),
        "risk_level_during_signin": rec.get("riskLevelDuringSignIn"),
        "risk_state": rec.get("riskState"),
        "status_error_code": error_code,
        "status_failure_reason": status.get("failureReason"),
        "status_additional_details": status.get("additionalDetails"),
        "device_id": device.get("deviceId"),
        "device_display_name": device.get("displayName"),
        "device_operating_system": device.get("operatingSystem"),
        "device_browser": device.get("browser"),
        "device_is_compliant": device.get("isCompliant"),
        "device_is_managed": device.get("isManaged"),
        "device_trust_type": device.get("trustType"),
        "location_city": location.get("city"),
        "location_state": location.get("state"),
        "location_country": location.get("countryOrRegion"),
        "location_latitude": fixed6(geo.get("latitude")),
        "location_longitude": fixed6(geo.get("longitude")),
        "success": error_code == 0 if error_code is not None else None,
    }
    policies = rec.get("appliedConditionalAccessPolicies")
    if isinstance(policies, list):
        attrs["applied_conditional_access_policies"] = [
            {"display_name": p.get("displayName"), "result": p.get("result")} for p in policies[:64] if isinstance(p, dict)
        ]
    outcome = "success" if error_code == 0 else f"failure {error_code}" if error_code is not None else "unknown"
    msg = f"Sign-in {outcome} for {upn or '?'} to {rec.get('appDisplayName') or '?'} from {rec.get('ipAddress') or '?'}"
    return make_event(
        data_type=ENTRA_SIGNIN, timestamp_desc=Desc.LAST_LOGIN, message=msg, timestamp=ts,
        source_short=SOURCE_SHORT, source_long="Entra ID sign-in log", parser="azure_entra_signin",
        evidence_path=ev_path, evidence_sha256=ev_sha, offset=index, user=upn,
        timezone=tz_of(raw_time), attrs=attrs,
    )


def _appgw(rec: dict, index: int, ev_path: str, ev_sha: str, result: ParseResult):
    raw_time = first(rec, "timeStamp", "time", "timestamp")
    ts = parse_time(raw_time)
    if ts is None:
        result.warn(f"record {index}: invalid timeStamp {raw_time!r}")
    props = rec.get("properties") if isinstance(rec.get("properties"), dict) else {}
    attrs: dict[str, Any] = {
        "raw_time": raw_time,
        "resource_id": rec.get("resourceId"),
        "operation_name": rec.get("operationName"),
        "category": rec.get("category"),
        "listener_name": rec.get("listenerName"),
        "rule_name": rec.get("ruleName"),
        "backend_pool_name": rec.get("backendPoolName"),
        "backend_setting_name": rec.get("backendSettingName"),
        "instance_id": props.get("instanceId"),
        "client_ip": props.get("clientIP"),
        "client_port": as_int(props.get("clientPort")),
        "http_method": props.get("httpMethod"),
        "request_uri": props.get("requestUri"),
        "original_request_uri_with_args": props.get("originalRequestUriWithArgs"),
        "request_query": props.get("requestQuery"),
        "user_agent": props.get("userAgent"),
        "http_status": as_int(props.get("httpStatus")),
        "http_version": props.get("httpVersion"),
        "received_bytes": as_int(props.get("receivedBytes")),
        "sent_bytes": as_int(props.get("sentBytes")),
        "time_taken": None if props.get("timeTaken") is None else str(props.get("timeTaken")),
        "waf_mode": props.get("WAFMode"),
        "transaction_id": props.get("transactionId"),
        "ssl_enabled": props.get("sslEnabled"),
        "ssl_cipher": props.get("sslCipher"),
        "ssl_protocol": props.get("sslProtocol"),
        "server_routed": props.get("serverRouted"),
        "server_status": props.get("serverStatus"),
        "original_host": props.get("originalHost"),
        "host": props.get("host"),
    }
    msg = (
        f"{props.get('httpMethod') or '-'} {props.get('originalRequestUriWithArgs') or props.get('requestUri') or '-'} "
        f"status={props.get('httpStatus')} from {props.get('clientIP') or '?'}"
    )
    return make_event(
        data_type=APPGW, timestamp_desc=Desc.EVENT, message=msg, timestamp=ts,
        source_short=SOURCE_SHORT, source_long="Azure Application Gateway access log", parser="azure_appgw",
        evidence_path=ev_path, evidence_sha256=ev_sha, offset=index, host=props.get("host"),
        timezone=tz_of(raw_time), attrs=attrs,
    )


# --------------------------------------------------------------------------- entry points

_KINDS: dict[str, tuple[Callable[[dict], bool], Callable]] = {
    APPGW: (is_appgw, _appgw),
    ENTRA_SIGNIN: (is_entra_signin, _entra_signin),
    ENTRA_AUDIT: (is_entra_audit, _entra_audit),
    ACTIVITY: (is_activity, _activity),
}


def classify(rec: dict) -> str | None:
    for name, (pred, _) in _KINDS.items():
        if pred(rec):
            return name
    return None


def _parse(source, want: str | None, evidence_path: str, evidence_sha256: str) -> ParseResult:
    evidence_path = evidence_path or source_name(source)
    result = ParseResult()
    with guard("azure log"):
        data = load_bytes(source)
        for index, rec in enumerate(iter_json_records(data, wrappers=("value", "records", "Records", "items"))):
            kind = classify(rec)
            if kind is None or (want is not None and kind != want):
                result.warn(f"record {index}: not a {want or 'recognised Azure'} record")
                continue
            result.events.append(_KINDS[kind][1](rec, index, evidence_path, evidence_sha256, result))
        if not result.events:
            raise ParserError(f"no {want or 'Azure'} records found")
    return result


def parse(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    """Auto-detect per record (mixed exports are allowed)."""
    return _parse(source, None, evidence_path, evidence_sha256)


def parse_activity_log(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    return _parse(source, ACTIVITY, evidence_path, evidence_sha256)


def parse_entra_audit(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    return _parse(source, ENTRA_AUDIT, evidence_path, evidence_sha256)


def parse_entra_signin(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    return _parse(source, ENTRA_SIGNIN, evidence_path, evidence_sha256)


def parse_appgw(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    return _parse(source, APPGW, evidence_path, evidence_sha256)
