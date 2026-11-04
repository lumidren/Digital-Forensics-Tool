"""Standalone parsers for iOS databases and plists (from an iTunes/Finder backup or extracted files).

All Core Data timestamps are Cocoa (seconds since 2001-01-01 UTC). Each function accepts a path or
bytes and returns a :class:`ParseResult`.
"""
from __future__ import annotations

from typing import Any, Callable

from veritas.timeline.schema import Desc

from .common import (
    ADDED,
    ParseResult,
    ParserError,
    cocoa_to_ns,
    col,
    columns,
    dt_to_ns,
    guard,
    ios_message_date_to_ns,
    load_plist,
    make_event,
    open_sqlite,
    round6,
    src_path,
    tables,
    text,
)

SOURCE_SHORT = "IOS"
JOINED_BY_USER = "Joined By User Time"
JOINED_BY_SYSTEM = "Joined By System Time"
LAST_JOINED = "Last Connection Time"


def _ev(result: ParseResult, *, data_type: str, desc: str, ts: int | None, msg: str, parser: str,
        path: str, sha: str, offset: int, attrs: dict[str, Any], user: str | None = None,
        source_long: str = "") -> None:
    result.events.append(make_event(
        data_type=data_type, timestamp_desc=desc, message=msg, timestamp=ts, source_short=SOURCE_SHORT,
        source_long=source_long or f"iOS {parser.replace('_', ' ')}", parser="ios_" + parser, evidence_path=path,
        evidence_sha256=sha, offset=offset, user=user, timezone="UTC" if ts is not None else None, attrs=attrs,
    ))


def _require(names: set[str], needed: set[str], what: str) -> None:
    if not (needed & names):
        raise ParserError(f"{what}: none of the expected tables {sorted(needed)} present")


# --------------------------------------------------------------------------- sms.db


def parse_sms(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("sms.db"):
        conn = open_sqlite(source)
        try:
            names = tables(conn)
            _require(names, {"message"}, "sms.db")
            handles: dict[int, dict[str, Any]] = {}
            if "handle" in names:
                for h in conn.execute("SELECT * FROM handle"):
                    handles[col(h, "ROWID")] = {"id": text(col(h, "id")), "service": text(col(h, "service"))}
            chats: dict[int, dict[str, Any]] = {}
            if {"chat", "chat_message_join"} <= names:
                for c in conn.execute(
                    "SELECT cmj.message_id AS mid, c.ROWID AS cid, c.chat_identifier AS ident, c.display_name AS dn "
                    "FROM chat_message_join cmj JOIN chat c ON c.ROWID = cmj.chat_id ORDER BY cmj.message_id, c.ROWID"
                ):
                    chats.setdefault(col(c, "mid"), {"chat_id": col(c, "cid"), "chat_identifier": text(col(c, "ident")),
                                                     "chat_display_name": text(col(c, "dn"))})
            elif "chat_message_join" in names:
                for c in conn.execute("SELECT message_id, chat_id FROM chat_message_join ORDER BY message_id, chat_id"):
                    chats.setdefault(col(c, "message_id"), {"chat_id": col(c, "chat_id")})
            mcols = columns(conn, "message")
            for row in conn.execute("SELECT * FROM message ORDER BY ROWID"):
                rid = col(row, "ROWID")
                handle = handles.get(col(row, "handle_id"), {})
                is_from_me = bool(col(row, "is_from_me"))
                attrs: dict[str, Any] = {
                    "rowid": rid, "guid": text(col(row, "guid")), "text": text(col(row, "text")),
                    "handle_id": col(row, "handle_id"), "handle": handle.get("id"),
                    "service": text(col(row, "service")) or handle.get("service"), "is_from_me": is_from_me,
                    "is_read": bool(col(row, "is_read")) if "is_read" in mcols else None,
                    "is_delivered": bool(col(row, "is_delivered")) if "is_delivered" in mcols else None,
                    "cache_has_attachments": col(row, "cache_has_attachments"), "raw_date": col(row, "date"),
                }
                attrs.update(chats.get(rid, {}))
                peer = handle.get("id") or attrs.get("chat_identifier") or "?"
                msg = f"{attrs['service'] or 'SMS'} {'to' if is_from_me else 'from'} {peer}: {(attrs['text'] or '')[:200]}"
                ts = ios_message_date_to_ns(col(row, "date"))
                _ev(result, data_type="ios:sms:message", desc=Desc.SENT if is_from_me else Desc.RECEIVED, ts=ts,
                    msg=msg, parser="sms", path=path, sha=evidence_sha256, offset=int(rid or 0), attrs=attrs)
                for field, desc in (("date_read", "Read Time"), ("date_delivered", "Delivered Time")):
                    t2 = ios_message_date_to_ns(col(row, field)) if field in mcols else None
                    if t2 is not None:
                        _ev(result, data_type="ios:sms:message", desc=desc, ts=t2, msg=msg, parser="sms", path=path,
                            sha=evidence_sha256, offset=int(rid or 0), attrs=attrs)
        finally:
            conn.close()
    return result


# --------------------------------------------------------------------------- CallHistory.storedata

CALL_TYPES = {1: "phone", 8: "facetime_video", 16: "facetime_audio"}


def parse_call_history(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("CallHistory.storedata"):
        conn = open_sqlite(source)
        try:
            _require(tables(conn), {"ZCALLRECORD"}, "CallHistory.storedata")
            for row in conn.execute("SELECT * FROM ZCALLRECORD ORDER BY Z_PK"):
                pk = col(row, "Z_PK")
                originated = bool(col(row, "ZORIGINATED"))
                answered = bool(col(row, "ZANSWERED"))
                duration = col(row, "ZDURATION")
                dur_ms = int(round(float(duration) * 1000)) if isinstance(duration, (int, float)) else None
                attrs = {
                    "pk": pk, "address": text(col(row, "ZADDRESS")), "name": text(col(row, "ZNAME")),
                    "duration_ms": dur_ms, "originated": originated, "answered": answered,
                    "call_type": col(row, "ZCALLTYPE"), "call_type_name": CALL_TYPES.get(col(row, "ZCALLTYPE")),
                    "service_provider": text(col(row, "ZSERVICE_PROVIDER")), "location": text(col(row, "ZLOCATION")),
                    "iso_country_code": text(col(row, "ZISO_COUNTRY_CODE")), "unique_id": text(col(row, "ZUNIQUE_ID")),
                }
                direction = "outgoing" if originated else ("incoming" if answered else "missed")
                attrs["direction"] = direction
                msg = f"Call {direction} {attrs['address'] or '?'} duration {(dur_ms or 0) // 1000}s"
                start = cocoa_to_ns(col(row, "ZDATE"))
                _ev(result, data_type="ios:callhistory:call", desc=Desc.START, ts=start, msg=msg, parser="call_history",
                    path=path, sha=evidence_sha256, offset=int(pk or 0), attrs=attrs)
                if start is not None and dur_ms:
                    _ev(result, data_type="ios:callhistory:call", desc=Desc.END, ts=start + dur_ms * 1_000_000, msg=msg,
                        parser="call_history", path=path, sha=evidence_sha256, offset=int(pk or 0), attrs=attrs)
        finally:
            conn.close()
    return result


# --------------------------------------------------------------------------- AddressBook.sqlitedb

AB_PROPERTY = {3: "phone", 4: "email", 5: "address", 22: "url"}


def parse_address_book(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("AddressBook.sqlitedb"):
        conn = open_sqlite(source)
        try:
            names = tables(conn)
            _require(names, {"ABPerson"}, "AddressBook.sqlitedb")
            multi: dict[int, dict[str, list[str]]] = {}
            if "ABMultiValue" in names:
                for mv in conn.execute("SELECT record_id, property, value FROM ABMultiValue ORDER BY record_id, UID"):
                    kind = AB_PROPERTY.get(col(mv, "property"))
                    if kind and col(mv, "value") is not None:
                        multi.setdefault(col(mv, "record_id"), {}).setdefault(kind + "s", []).append(text(col(mv, "value")))
            for row in conn.execute("SELECT * FROM ABPerson ORDER BY ROWID"):
                rid = col(row, "ROWID")
                attrs: dict[str, Any] = {
                    "rowid": rid, "first": text(col(row, "First")), "last": text(col(row, "Last")),
                    "middle": text(col(row, "Middle")), "organization": text(col(row, "Organization")),
                    "note": text(col(row, "Note")), "pii": True,
                }
                attrs.update(multi.get(rid, {}))
                name = " ".join(x for x in (attrs["first"], attrs["last"]) if x) or attrs["organization"] or "?"
                msg = f"Contact {name} phones={','.join(attrs.get('phones', [])) or '-'} emails={','.join(attrs.get('emails', [])) or '-'}"
                emitted = False
                for field, desc in (("CreationDate", Desc.CREATION), ("ModificationDate", Desc.MODIFICATION)):
                    ts = cocoa_to_ns(col(row, field))
                    if ts is not None:
                        emitted = True
                        _ev(result, data_type="ios:addressbook:contact", desc=desc, ts=ts, msg=msg, parser="address_book",
                            path=path, sha=evidence_sha256, offset=int(rid or 0), attrs=attrs)
                if not emitted:
                    _ev(result, data_type="ios:addressbook:contact", desc=Desc.NOT_A_TIME, ts=None, msg=msg,
                        parser="address_book", path=path, sha=evidence_sha256, offset=int(rid or 0), attrs=attrs)
        finally:
            conn.close()
    return result


# --------------------------------------------------------------------------- Photos.sqlite

PHOTO_KINDS = {0: "photo", 1: "video"}


def parse_photos(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("Photos.sqlite"):
        conn = open_sqlite(source)
        try:
            names = tables(conn)
            table = "ZASSET" if "ZASSET" in names else "ZGENERICASSET" if "ZGENERICASSET" in names else None
            if table is None:
                raise ParserError("Photos.sqlite: neither ZASSET nor ZGENERICASSET present")
            for row in conn.execute(f"SELECT * FROM {table} ORDER BY Z_PK"):
                pk = col(row, "Z_PK")
                lat, lon = col(row, "ZLATITUDE"), col(row, "ZLONGITUDE")
                has_loc = isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and lat != -180.0 and lon != -180.0 and not (lat == 0 and lon == 0)
                kind = col(row, "ZKIND")
                attrs = {
                    "pk": pk, "table": table, "filename": text(col(row, "ZFILENAME")), "directory": text(col(row, "ZDIRECTORY")),
                    "uuid": text(col(row, "ZUUID")), "kind": kind, "kind_name": PHOTO_KINDS.get(kind),
                    "width": col(row, "ZWIDTH"), "height": col(row, "ZHEIGHT"),
                    "latitude": round6(lat) if has_loc else None, "longitude": round6(lon) if has_loc else None,
                    "trashed": col(row, "ZTRASHEDSTATE"), "hidden": col(row, "ZHIDDEN"), "favorite": col(row, "ZFAVORITE"),
                }
                loc = f" at {attrs['latitude']},{attrs['longitude']}" if has_loc else ""
                msg = f"{(attrs['kind_name'] or 'asset').capitalize()} {attrs['directory'] or ''}/{attrs['filename'] or '?'}{loc}"
                for field, desc in (("ZDATECREATED", Desc.CREATION), ("ZADDEDDATE", ADDED), ("ZMODIFICATIONDATE", Desc.MODIFICATION)):
                    ts = cocoa_to_ns(col(row, field))
                    if ts is not None:
                        _ev(result, data_type="ios:photos:asset", desc=desc, ts=ts, msg=msg, parser="photos",
                            path=path, sha=evidence_sha256, offset=int(pk or 0), attrs=attrs)
        finally:
            conn.close()
    return result


# --------------------------------------------------------------------------- Wi-Fi plists


def _ssid(value: Any) -> str | None:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    return text(value)


def parse_wifi_plist(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    """``com.apple.wifi.plist`` (``List of known networks``) and ``com.apple.wifi.known-networks.plist``."""
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("wifi plist"):
        plist = load_plist(source)
        if not isinstance(plist, dict):
            raise ParserError("wifi plist: root is not a dictionary")
        networks: list[tuple[str, dict]] = []
        if isinstance(plist.get("List of known networks"), list):
            for n in plist["List of known networks"]:
                if isinstance(n, dict):
                    networks.append((_ssid(n.get("SSID_STR") or n.get("SSID")) or "?", n))
        else:
            for key in sorted(plist):
                if isinstance(plist[key], dict) and key.startswith("wifi.network."):
                    networks.append((_ssid(plist[key].get("SSID")) or key.rsplit(".", 1)[-1], plist[key]))
        if not networks:
            raise ParserError("wifi plist: no known networks")
        for index, (ssid, n) in enumerate(networks):
            os_specific = n.get("__OSSpecific__") if isinstance(n.get("__OSSpecific__"), dict) else {}
            bss = n.get("BSSList") if isinstance(n.get("BSSList"), list) else []
            attrs = {
                "ssid": ssid, "bssid": text(n.get("BSSID") or os_specific.get("BSSID")),
                "security": text(n.get("SupportedSecurityTypes") or n.get("SecurityMode")),
                "hidden": n.get("Hidden"), "channel": n.get("CHANNEL") or os_specific.get("CHANNEL"),
                "bssids": sorted({text(b.get("BSSID")) for b in bss if isinstance(b, dict) and b.get("BSSID")}),
                "captive": (n.get("CaptiveProfile") or {}).get("CaptiveNetwork") if isinstance(n.get("CaptiveProfile"), dict) else None,
            }
            msg = f"Known Wi-Fi network {ssid} ({attrs['security'] or 'unknown security'})"
            times = (
                ("AddedAt", ADDED), ("JoinedByUserAt", JOINED_BY_USER), ("JoinedBySystemAt", JOINED_BY_SYSTEM),
                ("UpdatedAt", Desc.MODIFICATION), ("lastJoined", LAST_JOINED), ("lastAutoJoined", JOINED_BY_SYSTEM),
            )
            emitted = False
            for key, desc in times:
                ts = dt_to_ns(n.get(key))
                if ts is not None:
                    emitted = True
                    _ev(result, data_type="ios:wifi:known_network", desc=desc, ts=ts, msg=msg, parser="wifi",
                        path=path, sha=evidence_sha256, offset=index, attrs=attrs)
            if not emitted:
                _ev(result, data_type="ios:wifi:known_network", desc=Desc.NOT_A_TIME, ts=None, msg=msg, parser="wifi",
                    path=path, sha=evidence_sha256, offset=index, attrs=attrs)
    return result


# --------------------------------------------------------------------------- com.apple.MobileBackup.plist


def parse_mobilebackup_plist(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    """On-device ``com.apple.MobileBackup.plist``: iCloud backup state and history."""
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("MobileBackup plist"):
        plist = load_plist(source)
        if not isinstance(plist, dict) or not ({"BackupStateInfo", "AccountEnabledDate"} & set(plist)):
            raise ParserError("not a com.apple.MobileBackup.plist")
        ts = dt_to_ns(plist.get("AccountEnabledDate"))
        if ts is not None:
            _ev(result, data_type="ios:mobilebackup:event", desc=Desc.CREATION, ts=ts, msg="iCloud backup enabled",
                parser="mobilebackup", path=path, sha=evidence_sha256, offset=0, attrs={"field": "AccountEnabledDate"})
        state = plist.get("BackupStateInfo") if isinstance(plist.get("BackupStateInfo"), dict) else {}
        ts = dt_to_ns(state.get("date"))
        if ts is not None:
            _ev(result, data_type="ios:mobilebackup:event", desc=Desc.START, ts=ts,
                msg=f"Backup state {state.get('state')} cloud={state.get('isCloud')}", parser="mobilebackup", path=path,
                sha=evidence_sha256, offset=0,
                attrs={"field": "BackupStateInfo.date", "state": state.get("state"), "is_cloud": state.get("isCloud"),
                       "is_background": state.get("isBackground")})
        for index, err in enumerate(state.get("errors") or [], 1):
            if not isinstance(err, dict):
                continue
            ts = dt_to_ns(err.get("date"))
            _ev(result, data_type="ios:mobilebackup:event", desc=Desc.END, ts=ts,
                msg=f"Backup result: {err.get('localizedDescription')} (code {err.get('code')})", parser="mobilebackup",
                path=path, sha=evidence_sha256, offset=index,
                attrs={"field": "BackupStateInfo.errors", "code": err.get("code"), "domain": err.get("domain"),
                       "description": err.get("localizedDescription")})
        if not result.events:
            result.warn("MobileBackup plist: no dated entries")
    return result


# --------------------------------------------------------------------------- Accounts3.sqlite


def parse_accounts(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("Accounts3.sqlite"):
        conn = open_sqlite(source)
        try:
            names = tables(conn)
            _require(names, {"ZACCOUNT"}, "Accounts3.sqlite")
            types = {}
            if "ZACCOUNTTYPE" in names:
                types = {col(t, "Z_PK"): (text(col(t, "ZACCOUNTTYPEDESCRIPTION")), text(col(t, "ZIDENTIFIER")))
                         for t in conn.execute("SELECT Z_PK, ZACCOUNTTYPEDESCRIPTION, ZIDENTIFIER FROM ZACCOUNTTYPE")}
            for row in conn.execute("SELECT * FROM ZACCOUNT ORDER BY Z_PK"):
                pk = col(row, "Z_PK")
                tdesc, tid = types.get(col(row, "ZACCOUNTTYPE"), (None, None))
                attrs = {
                    "pk": pk, "username": text(col(row, "ZUSERNAME")), "description": text(col(row, "ZACCOUNTDESCRIPTION")),
                    "identifier": text(col(row, "ZIDENTIFIER")), "owning_bundle_id": text(col(row, "ZOWNINGBUNDLEID")),
                    "account_type": tdesc, "account_type_identifier": tid, "active": col(row, "ZACTIVE"),
                    "authenticated": col(row, "ZAUTHENTICATED"),
                }
                msg = f"Account {tdesc or '?'} {attrs['username'] or attrs['description'] or ''} ({attrs['owning_bundle_id'] or '?'})"
                _ev(result, data_type="ios:accounts:account", desc=Desc.CREATION, ts=cocoa_to_ns(col(row, "ZDATE")),
                    msg=msg, parser="accounts", path=path, sha=evidence_sha256, offset=int(pk or 0), attrs=attrs,
                    user=attrs["username"])
        finally:
            conn.close()
    return result


# --------------------------------------------------------------------------- DataUsage.sqlite / netusage.sqlite


def parse_datausage(source, *, evidence_path: str = "", evidence_sha256: str = "", flavour: str = "datausage") -> ParseResult:
    """``DataUsage.sqlite`` and ``netusage.sqlite`` share ZPROCESS / ZLIVEUSAGE."""
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard(f"{flavour} sqlite"):
        conn = open_sqlite(source)
        try:
            names = tables(conn)
            _require(names, {"ZPROCESS"}, flavour)
            dt_proc = f"ios:{flavour}:process"
            procs: dict[int, tuple[str | None, str | None]] = {}
            for row in conn.execute("SELECT * FROM ZPROCESS ORDER BY Z_PK"):
                pk = col(row, "Z_PK")
                attrs = {"pk": pk, "bundle_name": text(col(row, "ZBUNDLENAME")), "process_name": text(col(row, "ZPROCNAME"))}
                procs[pk] = (attrs["bundle_name"], attrs["process_name"])
                msg = f"Process {attrs['process_name'] or '?'} ({attrs['bundle_name'] or '-'})"
                for field, desc in (("ZFIRSTTIMESTAMP", "First Seen Time"), ("ZTIMESTAMP", "Last Seen Time")):
                    ts = cocoa_to_ns(col(row, field))
                    if ts is not None:
                        _ev(result, data_type=dt_proc, desc=desc, ts=ts, msg=msg, parser=flavour, path=path,
                            sha=evidence_sha256, offset=int(pk or 0), attrs=attrs)
            if "ZLIVEUSAGE" in names:
                for row in conn.execute("SELECT * FROM ZLIVEUSAGE ORDER BY Z_PK"):
                    pk = col(row, "Z_PK")
                    bundle, proc = procs.get(col(row, "ZHASPROCESS"), (None, None))
                    attrs = {"pk": pk, "process_name": proc, "bundle_name": bundle, "kind": col(row, "ZKIND")}
                    for k in ("ZWIFIIN", "ZWIFIOUT", "ZWWANIN", "ZWWANOUT", "ZWIREDIN", "ZWIREDOUT"):
                        v = col(row, k)
                        if isinstance(v, (int, float)):
                            attrs[k[1:].lower() + "_bytes"] = int(v)
                    msg = (f"Network usage {proc or '?'} wifi in/out {attrs.get('wifiin_bytes', 0)}/{attrs.get('wifiout_bytes', 0)} "
                           f"wwan in/out {attrs.get('wwanin_bytes', 0)}/{attrs.get('wwanout_bytes', 0)}")
                    _ev(result, data_type=f"ios:{flavour}:live_usage", desc=Desc.MODIFICATION,
                        ts=cocoa_to_ns(col(row, "ZTIMESTAMP")), msg=msg, parser=flavour, path=path,
                        sha=evidence_sha256, offset=int(pk or 0), attrs=attrs)
        finally:
            conn.close()
    return result


def parse_netusage(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    return parse_datausage(source, evidence_path=evidence_path, evidence_sha256=evidence_sha256, flavour="netusage")


# --------------------------------------------------------------------------- NoteStore.sqlite


def parse_notes(source, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    """Notes metadata (title, snippet, dates, lock state). Note bodies are gzip'd protobuf: not decoded."""
    path = src_path(source, evidence_path)
    result = ParseResult()
    with guard("NoteStore.sqlite"):
        conn = open_sqlite(source)
        try:
            names = tables(conn)
            _require(names, {"ZICCLOUDSYNCINGOBJECT"}, "NoteStore.sqlite")
            ent = None
            if "Z_PRIMARYKEY" in names:
                r = conn.execute("SELECT Z_ENT FROM Z_PRIMARYKEY WHERE Z_NAME = 'ICNote'").fetchone()
                ent = r[0] if r else None
            cols = columns(conn, "ZICCLOUDSYNCINGOBJECT")
            title_col = "ZTITLE1" if "ZTITLE1" in cols else "ZTITLE"
            where = f"Z_ENT = {int(ent)}" if ent is not None else f"{title_col} IS NOT NULL"
            for row in conn.execute(f"SELECT * FROM ZICCLOUDSYNCINGOBJECT WHERE {where} ORDER BY Z_PK"):
                pk = col(row, "Z_PK")
                attrs = {
                    "pk": pk, "title": text(col(row, title_col)), "snippet": text(col(row, "ZSNIPPET")),
                    "identifier": text(col(row, "ZIDENTIFIER")),
                    "password_protected": bool(col(row, "ZISPASSWORDPROTECTED")),
                    "marked_for_deletion": bool(col(row, "ZMARKEDFORDELETION")),
                    "folder": col(row, "ZFOLDER"),
                }
                msg = f"Note '{attrs['title'] or '?'}'" + (" (locked)" if attrs["password_protected"] else "")
                created = None
                for field in ("ZCREATIONDATE3", "ZCREATIONDATE1", "ZCREATIONDATE"):
                    if field in cols:
                        created = cocoa_to_ns(col(row, field))
                        if created is not None:
                            break
                modified = None
                for field in ("ZMODIFICATIONDATE1", "ZMODIFICATIONDATE"):
                    if field in cols:
                        modified = cocoa_to_ns(col(row, field))
                        if modified is not None:
                            break
                emitted = False
                for ts, desc in ((created, Desc.CREATION), (modified, Desc.MODIFICATION)):
                    if ts is not None:
                        emitted = True
                        _ev(result, data_type="ios:notes:note", desc=desc, ts=ts, msg=msg, parser="notes", path=path,
                            sha=evidence_sha256, offset=int(pk or 0), attrs=attrs)
                if not emitted:
                    _ev(result, data_type="ios:notes:note", desc=Desc.NOT_A_TIME, ts=None, msg=msg, parser="notes",
                        path=path, sha=evidence_sha256, offset=int(pk or 0), attrs=attrs)
        finally:
            conn.close()
    return result


# --------------------------------------------------------------------------- dispatch by file name

FILE_PARSERS: dict[str, Callable[..., ParseResult]] = {
    "sms.db": parse_sms,
    "callhistory.storedata": parse_call_history,
    "addressbook.sqlitedb": parse_address_book,
    "photos.sqlite": parse_photos,
    "com.apple.wifi.plist": parse_wifi_plist,
    "com.apple.wifi.known-networks.plist": parse_wifi_plist,
    "com.apple.mobilebackup.plist": parse_mobilebackup_plist,
    "accounts3.sqlite": parse_accounts,
    "datausage.sqlite": parse_datausage,
    "netusage.sqlite": parse_netusage,
    "notestore.sqlite": parse_notes,
}


def parser_for(name: str) -> Callable[..., ParseResult] | None:
    return FILE_PARSERS.get(name.replace("\\", "/").rsplit("/", 1)[-1].lower())
