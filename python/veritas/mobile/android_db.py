"""Standalone parsers for Android app databases found in ``adb backup`` archives or ``adb pull`` trees.

Every function takes a path or bytes and returns a :class:`ParseResult`. They work on their own
(e.g. on ``testdata/corpus/plaso/android/*.db``) and are reused by :mod:`veritas.mobile.android_backup`.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

import defusedxml.ElementTree as SafeET
from typing import Any, Callable

from veritas.timeline.schema import Desc

from .common import (
    ParseResult,
    ParserError,
    col,
    columns,
    guard,
    make_event,
    ms_to_ns,
    open_sqlite,
    s_to_ns,
    src_path,
    tables,
    text,
)

SOURCE_SHORT = "ANDROID"
PARSER_PREFIX = "android_"

SMS_TYPES = {0: "all", 1: "received", 2: "sent", 3: "draft", 4: "outbox", 5: "failed", 6: "queued"}
CALL_TYPES = {1: "incoming", 2: "outgoing", 3: "missed", 4: "voicemail", 5: "rejected", 6: "blocked", 7: "answered_externally"}
MMS_BOX = {1: "inbox", 2: "sent", 3: "drafts", 4: "outbox"}
DOWNLOAD_STATUS = {
    190: "pending", 192: "running", 193: "paused", 194: "waiting_to_retry", 195: "waiting_for_network",
    196: "queued_for_wifi", 200: "success", 400: "bad_request", 406: "not_acceptable", 488: "file_already_exists",
    489: "cannot_resume", 490: "canceled", 491: "unknown_error", 492: "file_error", 493: "unhandled_redirect",
    494: "unhandled_http_code", 495: "http_data_error", 496: "http_exception", 497: "too_many_redirects",
    498: "insufficient_space", 499: "device_not_found",
}
MIME_NAME = "vnd.android.cursor.item/name"
MIME_PHONE = "vnd.android.cursor.item/phone_v2"
MIME_EMAIL = "vnd.android.cursor.item/email_v2"


def _ev(result: ParseResult, *, data_type: str, desc: str, ts: int | None, msg: str, parser: str,
        path: str, sha: str, offset: int, attrs: dict[str, Any], user: str | None = None) -> None:
    result.events.append(make_event(
        data_type=data_type, timestamp_desc=desc, message=msg, timestamp=ts, source_short=SOURCE_SHORT,
        source_long=f"Android {parser.replace('_', ' ')}", parser=PARSER_PREFIX + parser, evidence_path=path,
        evidence_sha256=sha, offset=offset, user=user, timezone="UTC" if ts is not None else None, attrs=attrs,
    ))


# --------------------------------------------------------------------------- mmssms.db


def parse_mmssms(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("mmssms.db"):
        conn = open_sqlite(source)
        try:
            names = tables(conn)
            if "sms" not in names and "pdu" not in names:
                raise ParserError("mmssms.db: neither sms nor pdu table present")
            if "sms" in names:
                cols = columns(conn, "sms")
                for row in conn.execute("SELECT * FROM sms ORDER BY _id"):
                    mtype = col(row, "type")
                    kind = SMS_TYPES.get(mtype, str(mtype))
                    attrs = {
                        "id": col(row, "_id"), "thread_id": col(row, "thread_id"), "address": text(col(row, "address")),
                        "body": text(col(row, "body")), "type": mtype, "type_name": kind,
                        "read": bool(col(row, "read")) if col(row, "read") is not None else None,
                        "seen": bool(col(row, "seen")) if "seen" in cols and col(row, "seen") is not None else None,
                        "status": col(row, "status"), "subject": text(col(row, "subject")),
                        "service_center": text(col(row, "service_center")), "date_ms": col(row, "date"),
                        "date_sent_ms": col(row, "date_sent") if "date_sent" in cols else None,
                        "protocol": col(row, "protocol"), "locked": col(row, "locked"),
                    }
                    direction = "from" if mtype == 1 else "to"
                    body = attrs["body"] or ""
                    msg = f"SMS {kind} {direction} {attrs['address'] or '?'}: {body[:200]}"
                    desc = Desc.RECEIVED if mtype == 1 else Desc.SENT if mtype == 2 else Desc.CREATION
                    ts = ms_to_ns(col(row, "date"))
                    _ev(result, data_type="android:messaging:sms", desc=desc, ts=ts, msg=msg, parser="sms",
                        path=path, sha=evidence_sha256, offset=int(col(row, "_id") or 0), attrs=attrs)
                    sent_ts = ms_to_ns(attrs["date_sent_ms"])
                    if mtype == 1 and sent_ts is not None:
                        _ev(result, data_type="android:messaging:sms", desc=Desc.SENT, ts=sent_ts, msg=msg,
                            parser="sms", path=path, sha=evidence_sha256, offset=int(col(row, "_id") or 0),
                            attrs=attrs)
            if "pdu" in names:
                parts: dict[int, list[dict[str, Any]]] = {}
                if "part" in names:
                    for p in conn.execute("SELECT * FROM part ORDER BY mid, seq, _id"):
                        parts.setdefault(col(p, "mid"), []).append({
                            "content_type": text(col(p, "ct")), "name": text(col(p, "name") or col(p, "cl")),
                            "text": text(col(p, "text")), "data_path": text(col(p, "_data")),
                        })
                addrs: dict[int, list[str]] = {}
                if "addr" in names:
                    for a in conn.execute("SELECT msg_id, address, type FROM addr ORDER BY msg_id, _id"):
                        if col(a, "address") and col(a, "address") != "insert-address-token":
                            addrs.setdefault(col(a, "msg_id"), []).append(text(col(a, "address")))
                for row in conn.execute("SELECT * FROM pdu ORDER BY _id"):
                    pid = col(row, "_id")
                    box = col(row, "msg_box")
                    plist = parts.get(pid, [])
                    body = " ".join(p["text"] for p in plist if p.get("text") and (p.get("content_type") or "").startswith("text/plain"))
                    attrs = {
                        "id": pid, "thread_id": col(row, "thread_id"), "msg_box": box, "msg_box_name": MMS_BOX.get(box),
                        "subject": text(col(row, "sub")), "read": col(row, "read"), "message_id": text(col(row, "m_id")),
                        "message_size": col(row, "m_size"), "addresses": addrs.get(pid, []), "parts": plist[:64],
                        "body": body or None, "date_s": col(row, "date"),
                    }
                    msg = f"MMS {MMS_BOX.get(box, box)} {', '.join(attrs['addresses']) or '?'}: {(body or attrs['subject'] or '')[:200]}"
                    desc = Desc.RECEIVED if box == 1 else Desc.SENT if box == 2 else Desc.CREATION
                    _ev(result, data_type="android:messaging:mms", desc=desc, ts=s_to_ns(col(row, "date")), msg=msg,
                        parser="mms", path=path, sha=evidence_sha256, offset=int(pid or 0), attrs=attrs)
        finally:
            conn.close()
    return result


# --------------------------------------------------------------------------- calls (contacts2.db / calllog.db)


def _parse_calls(conn, result: ParseResult, path: str, sha: str) -> None:
    for row in conn.execute("SELECT * FROM calls ORDER BY _id"):
        ctype = col(row, "type")
        kind = CALL_TYPES.get(ctype, str(ctype))
        duration = col(row, "duration")
        attrs = {
            "id": col(row, "_id"), "number": text(col(row, "number")), "name": text(col(row, "name")),
            "type": ctype, "type_name": kind, "duration_s": duration, "new": col(row, "new"),
            "country_iso": text(col(row, "countryiso")), "geocoded_location": text(col(row, "geocoded_location")),
            "normalized_number": text(col(row, "normalized_number")), "date_ms": col(row, "date"),
            "is_read": col(row, "is_read"), "phone_account": text(col(row, "subscription_component_name")),
        }
        who = attrs["name"] or attrs["number"] or "?"
        msg = f"Call {kind} {who} ({attrs['number'] or '?'}) duration {duration or 0}s"
        start = ms_to_ns(col(row, "date"))
        off = int(col(row, "_id") or 0)
        _ev(result, data_type="android:event:call", desc=Desc.START, ts=start, msg=msg, parser="call_log",
            path=path, sha=sha, offset=off, attrs=attrs)
        if start is not None and isinstance(duration, int) and duration > 0:
            _ev(result, data_type="android:event:call", desc=Desc.END, ts=start + duration * 1_000_000_000,
                msg=msg, parser="call_log", path=path, sha=sha, offset=off, attrs=attrs)


def _parse_contacts(conn, result: ParseResult, path: str, sha: str) -> None:
    names = tables(conn)
    if not {"raw_contacts", "data", "mimetypes"} <= names:
        return
    rc_cols = columns(conn, "raw_contacts")
    contacts: dict[int, dict[str, Any]] = {}
    for row in conn.execute("SELECT * FROM raw_contacts ORDER BY _id"):
        contacts[col(row, "_id")] = {
            "id": col(row, "_id"), "account_name": text(col(row, "account_name")) if "account_name" in rc_cols else None,
            "account_type": text(col(row, "account_type")) if "account_type" in rc_cols else None,
            "display_name": text(col(row, "display_name")), "deleted": col(row, "deleted"),
            "times_contacted": col(row, "times_contacted"), "last_time_contacted_ms": col(row, "last_time_contacted"),
            "starred": col(row, "starred"), "phones": [], "emails": [],
        }
    sql = (
        "SELECT d.raw_contact_id AS rid, m.mimetype AS mt, d.data1 AS d1, d.data2 AS d2, d.data3 AS d3 "
        "FROM data d JOIN mimetypes m ON d.mimetype_id = m._id ORDER BY d.raw_contact_id, d._id"
    )
    for row in conn.execute(sql):
        c = contacts.get(col(row, "rid"))
        if c is None:
            continue
        mt = col(row, "mt")
        if mt == MIME_NAME:
            c["display_name"] = c["display_name"] or text(col(row, "d1"))
            c["given_name"] = text(col(row, "d2"))
            c["family_name"] = text(col(row, "d3"))
        elif mt == MIME_PHONE and col(row, "d1"):
            c["phones"].append(text(col(row, "d1")))
        elif mt == MIME_EMAIL and col(row, "d1"):
            c["emails"].append(text(col(row, "d1")))
    for cid in sorted(contacts, key=lambda k: (k is None, k)):
        c = contacts[cid]
        msg = f"Contact {c['display_name'] or '?'} phones={','.join(c['phones']) or '-'} emails={','.join(c['emails']) or '-'}"
        ts = ms_to_ns(c["last_time_contacted_ms"])
        _ev(result, data_type="android:contacts:contact", desc=Desc.LAST_VISITED if ts else Desc.NOT_A_TIME, ts=ts,
            msg=msg, parser="contacts", path=path, sha=sha, offset=int(cid or 0), attrs=c)


def parse_contacts2(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    """contacts2.db: ``calls`` (pre-Android 7 call log), raw_contacts + data + mimetypes."""
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("contacts2.db"):
        conn = open_sqlite(source)
        try:
            names = tables(conn)
            if "calls" not in names and "raw_contacts" not in names:
                raise ParserError("contacts2.db: neither calls nor raw_contacts table present")
            if "calls" in names:
                _parse_calls(conn, result, path, evidence_sha256)
            if "raw_contacts" in names:
                _parse_contacts(conn, result, path, evidence_sha256)
                if not {"data", "mimetypes"} <= names:
                    result.warn("contacts2.db: raw_contacts without data/mimetypes tables")
        finally:
            conn.close()
    return result


def parse_calllog(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    """calllog.db (Android 7+)."""
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("calllog.db"):
        conn = open_sqlite(source)
        try:
            if "calls" not in tables(conn):
                raise ParserError("calllog.db: no calls table")
            _parse_calls(conn, result, path, evidence_sha256)
        finally:
            conn.close()
    return result


# --------------------------------------------------------------------------- downloads.db


def parse_downloads(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("downloads.db"):
        conn = open_sqlite(source)
        try:
            if "downloads" not in tables(conn):
                raise ParserError("downloads.db: no downloads table")
            for row in conn.execute("SELECT * FROM downloads ORDER BY _id"):
                status = col(row, "status")
                attrs = {
                    "id": col(row, "_id"), "uri": text(col(row, "uri")), "local_path": text(col(row, "_data")),
                    "mime_type": text(col(row, "mimetype")), "status": status,
                    "status_name": DOWNLOAD_STATUS.get(status), "total_bytes": col(row, "total_bytes"),
                    "current_bytes": col(row, "current_bytes"), "title": text(col(row, "title")),
                    "description": text(col(row, "description")), "notification_package": text(col(row, "notificationpackage")),
                    "user_agent": text(col(row, "useragent")), "referer": text(col(row, "referer")),
                    "deleted": col(row, "deleted"), "error_msg": text(col(row, "errorMsg")), "lastmod_ms": col(row, "lastmod"),
                }
                msg = f"Download {attrs['uri'] or '?'} -> {attrs['local_path'] or '-'} status={status} by {attrs['notification_package'] or '?'}"
                _ev(result, data_type="android:download", desc=Desc.MODIFICATION, ts=ms_to_ns(col(row, "lastmod")),
                    msg=msg, parser="downloads", path=path, sha=evidence_sha256, offset=int(col(row, "_id") or 0),
                    attrs=attrs)
        finally:
            conn.close()
    return result


# --------------------------------------------------------------------------- webview.db


def parse_webview(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("webview.db"):
        conn = open_sqlite(source)
        try:
            names = tables(conn)
            if not ({"cookies", "formdata", "password", "httpauth"} & names):
                raise ParserError("webview.db: no webview tables")
            if "cookies" in names:
                for row in conn.execute("SELECT * FROM cookies ORDER BY _id"):
                    attrs = {
                        "id": col(row, "_id"), "name": text(col(row, "name")), "value": text(col(row, "value")),
                        "domain": text(col(row, "domain")), "path": text(col(row, "path")),
                        "secure": bool(col(row, "secure")), "expires_ms": col(row, "expires"),
                    }
                    ts = ms_to_ns(col(row, "expires"))
                    msg = f"WebView cookie {attrs['domain']}{attrs['path']} {attrs['name']}"
                    _ev(result, data_type="android:webview:cookie", desc=Desc.EXPIRATION, ts=ts, msg=msg,
                        parser="webview", path=path, sha=evidence_sha256, offset=int(col(row, "_id") or 0), attrs=attrs)
            if "formdata" in names:
                urls = {}
                if "formurl" in names:
                    urls = {col(r, "_id"): text(col(r, "url")) for r in conn.execute("SELECT _id, url FROM formurl")}
                for row in conn.execute("SELECT * FROM formdata ORDER BY _id"):
                    attrs = {
                        "id": col(row, "_id"), "url": urls.get(col(row, "urlid")), "name": text(col(row, "name")),
                        "value": text(col(row, "value")), "pii": True,
                    }
                    msg = f"WebView form data {attrs['name']}={attrs['value']} on {attrs['url'] or '?'}"
                    _ev(result, data_type="android:webview:formdata", desc=Desc.NOT_A_TIME, ts=None, msg=msg,
                        parser="webview", path=path, sha=evidence_sha256, offset=int(col(row, "_id") or 0), attrs=attrs)
            for table in ("password", "httpauth"):
                if table not in names:
                    continue
                for row in conn.execute(f'SELECT * FROM "{table}" ORDER BY _id'):  # nosec B608 - table name chosen from a fixed tuple
                    attrs = {
                        "id": col(row, "_id"), "table": table, "host": text(col(row, "host")),
                        "realm": text(col(row, "realm")), "username": text(col(row, "username")),
                        "has_password": bool(col(row, "password")), "pii": True,
                    }
                    msg = f"WebView stored credential for {attrs['username'] or '?'} at {attrs['host'] or '?'}"
                    _ev(result, data_type="android:webview:credential", desc=Desc.NOT_A_TIME, ts=None, msg=msg,
                        parser="webview", path=path, sha=evidence_sha256, offset=int(col(row, "_id") or 0), attrs=attrs)
        finally:
            conn.close()
    return result


# --------------------------------------------------------------------------- AOSP Browser (browser2.db)


def parse_browser(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    """AOSP stock browser ``browser2.db`` / ``browser.db``: history and bookmarks."""
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("browser db"):
        conn = open_sqlite(source)
        try:
            names = tables(conn)
            if not ({"history", "bookmarks"} & names):
                raise ParserError("browser db: no history or bookmarks table")
            if "history" in names:
                for row in conn.execute("SELECT * FROM history ORDER BY _id"):
                    attrs = {
                        "id": col(row, "_id"), "url": text(col(row, "url")), "title": text(col(row, "title")),
                        "visits": col(row, "visits"), "user_entered": col(row, "user_entered"),
                    }
                    msg = f"Visited {attrs['url'] or '?'} ({attrs['title'] or ''}) visits={attrs['visits']}"
                    off = int(col(row, "_id") or 0)
                    _ev(result, data_type="android:browser:history", desc=Desc.LAST_VISITED, ts=ms_to_ns(col(row, "date")),
                        msg=msg, parser="browser", path=path, sha=evidence_sha256, offset=off, attrs=attrs)
                    created = ms_to_ns(col(row, "created"))
                    if created is not None:
                        _ev(result, data_type="android:browser:history", desc=Desc.CREATION, ts=created, msg=msg,
                            parser="browser", path=path, sha=evidence_sha256, offset=off, attrs=attrs)
            if "bookmarks" in names:
                bcols = columns(conn, "bookmarks")
                for row in conn.execute("SELECT * FROM bookmarks ORDER BY _id"):
                    if "folder" in bcols and col(row, "folder"):
                        continue
                    attrs = {"id": col(row, "_id"), "url": text(col(row, "url")), "title": text(col(row, "title")),
                             "deleted": col(row, "deleted")}
                    msg = f"Bookmark {attrs['title'] or ''} {attrs['url'] or '?'}"
                    ts = ms_to_ns(col(row, "created"))
                    _ev(result, data_type="android:browser:bookmark", desc=Desc.CREATION, ts=ts, msg=msg,
                        parser="browser", path=path, sha=evidence_sha256, offset=int(col(row, "_id") or 0), attrs=attrs)
        finally:
            conn.close()
    return result


# --------------------------------------------------------------------------- packages.xml


def _hex_ms(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return ms_to_ns(int(value, 16))
    except ValueError:
        return None


def parse_packages_xml(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    """``/data/system/packages.xml`` (text form). Binary ABX (Android 12+) is reported as unsupported."""
    from .common import _raw  # local import keeps the public surface small

    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("packages.xml"):
        data = _raw(source, 64 * 1024 * 1024)
        if data.startswith(b"ABX"):
            raise ParserError("packages.xml is in binary ABX format (Android 12+); convert with abx2xml first")
        if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
            raise ParserError("packages.xml with DTD refused")
        try:
            root = SafeET.fromstring(data)
        except ET.ParseError as exc:
            raise ParserError(f"packages.xml: invalid XML: {exc}") from exc
        if root.tag != "packages":
            raise ParserError(f"packages.xml: unexpected root <{root.tag}>")
        for index, pkg in enumerate(root.iter("package")):
            name = pkg.get("name")
            if not name:
                continue
            perms = sorted({p.get("name") for p in pkg.iter("item") if p.get("name")})
            attrs = {
                "package": name, "code_path": pkg.get("codePath"), "version": pkg.get("version"),
                "user_id": pkg.get("userId") or pkg.get("sharedUserId"), "installer": pkg.get("installer") or pkg.get("installInitiator"),
                "flags": pkg.get("flags"), "first_install_hex": pkg.get("it"), "last_update_hex": pkg.get("ut"),
                "timestamp_hex": pkg.get("ft"), "permissions": perms[:256],
            }
            msg = f"Package {name} version {attrs['version'] or '?'} at {attrs['code_path'] or '?'}"
            pairs = ((Desc.INSTALLATION, _hex_ms(pkg.get("it"))), (Desc.MODIFICATION, _hex_ms(pkg.get("ut"))))
            emitted = False
            for desc, ts in pairs:
                if ts is not None:
                    emitted = True
                    _ev(result, data_type="android:app:package", desc=desc, ts=ts, msg=msg, parser="packages",
                        path=path, sha=evidence_sha256, offset=index, attrs=attrs)
            if not emitted:
                _ev(result, data_type="android:app:package", desc=Desc.NOT_A_TIME, ts=None, msg=msg,
                    parser="packages", path=path, sha=evidence_sha256, offset=index, attrs=attrs)
    return result


# --------------------------------------------------------------------------- dispatch by file name

DB_PARSERS: dict[str, Callable[..., ParseResult]] = {
    "mmssms.db": parse_mmssms,
    "contacts2.db": parse_contacts2,
    "calllog.db": parse_calllog,
    "downloads.db": parse_downloads,
    "webview.db": parse_webview,
    "browser2.db": parse_browser,
    "browser.db": parse_browser,
    "packages.xml": parse_packages_xml,
}


def parser_for(name: str) -> Callable[..., ParseResult] | None:
    return DB_PARSERS.get(name.replace("\\", "/").rsplit("/", 1)[-1].lower())
