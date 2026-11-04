"""Chromium-family browser databases: History, Cookies, Web Data, Login Data.

Works for Chrome, Edge (Chromium), Brave, Opera, Vivaldi: they share the schema. Schema
variants are handled by looking at the columns that exist (``downloads`` changed shape around
Chrome 26, cookies gained/lost columns, etc.); any missing column simply yields ``None``.

Timestamps in History / Cookies / Login Data are WebKit microseconds (since 1601-01-01);
``Web Data`` autofill uses Unix seconds.
"""
from __future__ import annotations

import pathlib
from typing import Any, Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.parsers.sqlite_safe import col, columns, has_table, is_sqlite, open_sqlite, rows, to_int
from veritas.timeline.schema import Desc, Event, unix_to_ns, webkit_us_to_ns

PAGE_TRANSITION_CORE = {
    0: "LINK", 1: "TYPED", 2: "AUTO_BOOKMARK", 3: "AUTO_SUBFRAME", 4: "MANUAL_SUBFRAME",
    5: "GENERATED", 6: "START_PAGE", 7: "FORM_SUBMIT", 8: "RELOAD", 9: "KEYWORD", 10: "KEYWORD_GENERATED",
}
PAGE_TRANSITION_QUALIFIERS = [
    (0x01000000, "FORWARD_BACK"), (0x02000000, "FROM_ADDRESS_BAR"), (0x04000000, "HOME_PAGE"),
    (0x08000000, "FROM_API"), (0x10000000, "CHAIN_START"), (0x20000000, "CHAIN_END"),
    (0x40000000, "CLIENT_REDIRECT"), (0x80000000, "SERVER_REDIRECT"),
]
DOWNLOAD_STATES = {0: "IN_PROGRESS", 1: "COMPLETE", 2: "CANCELLED", 3: "INTERRUPTED", 4: "INTERRUPTED"}
DANGER_TYPES = {
    0: "NOT_DANGEROUS", 1: "DANGEROUS_FILE", 2: "DANGEROUS_URL", 3: "DANGEROUS_CONTENT",
    4: "MAYBE_DANGEROUS_CONTENT", 5: "UNCOMMON_CONTENT", 6: "USER_VALIDATED", 7: "DANGEROUS_HOST",
    8: "POTENTIALLY_UNWANTED", 9: "ALLOWLISTED_BY_POLICY", 10: "ASYNC_SCANNING",
    11: "BLOCKED_PASSWORD_PROTECTED", 12: "BLOCKED_TOO_LARGE", 13: "SENSITIVE_CONTENT_WARNING",
    14: "SENSITIVE_CONTENT_BLOCK", 15: "DEEP_SCANNED_SAFE", 16: "DEEP_SCANNED_OPENED_DANGEROUS",
    17: "PROMPT_FOR_SCANNING", 18: "BLOCKED_UNSUPPORTED_FILETYPE", 19: "DANGEROUS_ACCOUNT_COMPROMISE",
}
VISIT_SOURCES = {0: "SYNCED", 1: "BROWSED", 2: "EXTENSION", 3: "FIREFOX_IMPORTED", 4: "IE_IMPORTED", 5: "SAFARI_IMPORTED"}


def transition_name(value: int | None) -> str:
    if value is None:
        return ""
    core = PAGE_TRANSITION_CORE.get(value & 0xFF, f"UNKNOWN_{value & 0xFF}")
    quals = [name for bit, name in PAGE_TRANSITION_QUALIFIERS if value & bit]
    return core if not quals else core + " (" + ", ".join(quals) + ")"


def _ws(us: Any) -> int | None:
    """WebKit microseconds -> ns, treating 0/None/negative as 'no timestamp'."""
    v = to_int(us)
    if not v or v < 0:
        return None
    return webkit_us_to_ns(v)


class ChromiumHistoryParser(BaseParser):
    name = "chromium_history"
    version = "1.0"
    source_short = "WEBHIST"
    source_long = "Chrome History"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        if not is_sqlite(head_bytes):
            return False
        base = pathlib.Path(path).name.lower()
        return base.startswith("history") or base == "archived history"

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            visits = has_table(conn, "urls") and has_table(conn, "visits")
            downloads = has_table(conn, "downloads")
            if not visits and not downloads:
                raise ParserError("chromium_history: no urls/visits/downloads tables")
            if visits:
                yield from self._visits(conn)
            if downloads:
                yield from self._downloads(conn)

    def _visits(self, conn) -> Iterator[Event]:
        has_source = has_table(conn, "visit_source")
        vcols = columns(conn, "visits")
        extra = ", visits.visit_duration AS visit_duration" if "visit_duration" in vcols else ", NULL AS visit_duration"
        src = "LEFT JOIN visit_source ON visits.id = visit_source.id" if has_source else ""
        src_col = ", visit_source.source AS visit_source" if has_source else ", NULL AS visit_source"
        sql = (
            "SELECT visits.id AS visit_id, visits.visit_time, visits.from_visit, visits.transition, "  # nosec B608 - fragments are code constants chosen by schema checks
            "urls.id AS url_id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.hidden"
            f"{extra}{src_col} FROM visits JOIN urls ON visits.url = urls.id {src} ORDER BY visits.id"
        )
        for row in rows(conn, sql):
            try:
                ts = _ws(col(row, "visit_time"))
                transition = to_int(col(row, "transition"), 0) or 0
                url = col(row, "url") or ""
                title = col(row, "title") or ""
                attrs = {
                    "url": url,
                    "title": title,
                    "visit_id": to_int(col(row, "visit_id")),
                    "url_id": to_int(col(row, "url_id")),
                    "from_visit": to_int(col(row, "from_visit"), 0) or 0,
                    "typed_count": to_int(col(row, "typed_count"), 0),
                    "visit_count": to_int(col(row, "visit_count"), 0),
                    "url_hidden": bool(to_int(col(row, "hidden"), 0)),
                    "page_transition_type": transition & 0xFF,
                    "page_transition": transition_name(transition),
                    "visit_duration_us": to_int(col(row, "visit_duration")),
                    "visit_source": VISIT_SOURCES.get(to_int(col(row, "visit_source"), -1)),
                }
                msg = f"{url} ({title})" if title else url
                msg += f" [count: {attrs['visit_count']}]"
                if transition & 0xFF == 1:
                    msg += " (URL typed)"
                msg += f" Type: [{transition_name(transition)}]"
                yield self.event("chrome:history:page_visited", Desc.LAST_VISITED, msg, ts,
                                 offset=int(attrs["visit_id"] or 0), attrs=attrs)
            except Exception as exc:  # noqa: BLE001
                self.warn(f"visits row: {exc}")

    def _downloads(self, conn) -> Iterator[Event]:
        dcols = columns(conn, "downloads")
        new_schema = "target_path" in dcols
        chains = has_table(conn, "downloads_url_chains")
        for row in rows(conn, "SELECT * FROM downloads ORDER BY id"):
            try:
                did = to_int(col(row, "id"), 0) or 0
                url = col(row, "url") if not new_schema else None
                if chains and url is None:
                    chain = [r[0] for r in rows(conn, "SELECT url FROM downloads_url_chains WHERE id=? ORDER BY chain_index", (did,))]
                    url = chain[-1] if chain else ""
                full_path = col(row, "target_path") if new_schema else col(row, "full_path")
                state = to_int(col(row, "state"), 0) or 0
                danger = to_int(col(row, "danger_type"))
                attrs = {
                    "url": url or "",
                    "full_path": full_path or "",
                    "current_path": col(row, "current_path") if new_schema else None,
                    "received_bytes": to_int(col(row, "received_bytes"), 0),
                    "total_bytes": to_int(col(row, "total_bytes"), 0),
                    "state": state,
                    "state_name": DOWNLOAD_STATES.get(state, "UNKNOWN"),
                    "danger_type": danger,
                    "danger_type_name": DANGER_TYPES.get(danger, "UNKNOWN") if danger is not None else None,
                    "interrupt_reason": to_int(col(row, "interrupt_reason")),
                    "opened": bool(to_int(col(row, "opened"), 0)),
                    "referrer": col(row, "referrer"),
                    "tab_url": col(row, "tab_url"),
                    "mime_type": col(row, "mime_type"),
                    "download_id": did,
                }
                msg = (f"{attrs['url']} ({attrs['full_path']}). Received: {attrs['received_bytes']} bytes "
                       f"out of: {attrs['total_bytes']} bytes.")
                if new_schema:
                    start = _ws(col(row, "start_time"))
                else:  # Chrome <= 26 stored Unix seconds here
                    raw_start = to_int(col(row, "start_time"))
                    start = unix_to_ns(raw_start) if raw_start else None
                if start is not None:
                    yield self.event("chrome:history:file_downloaded", Desc.START, msg, start, offset=did, attrs=attrs)
                end = _ws(col(row, "end_time"))
                if end is not None:
                    yield self.event("chrome:history:file_downloaded", Desc.END, msg, end, offset=did, attrs=attrs)
                last_access = _ws(col(row, "last_access_time"))
                if last_access is not None:
                    yield self.event("chrome:history:file_downloaded", Desc.ACCESS, msg, last_access, offset=did, attrs=attrs)
                if start is None and end is None:
                    yield self.event("chrome:history:file_downloaded", Desc.NOT_A_TIME, msg, None, offset=did, attrs=attrs)
            except Exception as exc:  # noqa: BLE001
                self.warn(f"downloads row: {exc}")


class ChromiumCookiesParser(BaseParser):
    name = "chromium_cookies"
    version = "1.0"
    source_short = "WEBHIST"
    source_long = "Chrome Cookies"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        name = pathlib.Path(path).name.lower()
        return is_sqlite(head_bytes) and name.startswith("cookies") and not name.endswith(".sqlite")

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            if not has_table(conn, "cookies"):
                raise ParserError("chromium_cookies: no cookies table")
            if "host_key" not in columns(conn, "cookies"):
                raise ParserError("chromium_cookies: cookies table is not Chromium-shaped")
            for idx, row in enumerate(rows(conn, "SELECT rowid AS rid, * FROM cookies ORDER BY rowid"), 1):
                try:
                    host = col(row, "host_key") or ""
                    name = col(row, "name") or ""
                    path_ = col(row, "path") or "/"
                    value = col(row, "value") or ""
                    secure = bool(to_int(col(row, "is_secure"), to_int(col(row, "secure"), 0)))
                    attrs = {
                        "host": host,
                        "cookie_name": name,
                        "data": value,
                        "path": path_,
                        "secure": secure,
                        "httponly": bool(to_int(col(row, "is_httponly"), to_int(col(row, "httponly"), 0))),
                        "persistent": bool(to_int(col(row, "is_persistent"), 0)),
                        "has_expires": bool(to_int(col(row, "has_expires"), 0)),
                        "priority": to_int(col(row, "priority")),
                        "samesite": to_int(col(row, "samesite")),
                        "url": ("https://" if secure else "http://") + host.lstrip(".") + path_,
                        "encrypted": bool(col(row, "encrypted_value")) and not value,
                    }
                    msg = (f"{attrs['url']} ({name}) Flags: [HTTP only] = {attrs['httponly']} "
                           f"[Persistent] = {attrs['persistent']}")
                    rid = to_int(col(row, "rid"), idx) or idx
                    for column, desc in (("creation_utc", Desc.CREATION), ("last_access_utc", Desc.ACCESS),
                                         ("expires_utc", Desc.EXPIRATION)):
                        ts = _ws(col(row, column))
                        if ts is not None:
                            yield self.event("chrome:cookie:entry", desc, msg, ts, offset=rid, attrs=attrs)
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"cookies row {idx}: {exc}")


def _logins(parser: BaseParser, conn) -> Iterator[Event]:
    for idx, row in enumerate(rows(conn, "SELECT rowid AS rid, * FROM logins ORDER BY rowid"), 1):
        try:
            attrs = {
                "origin_url": col(row, "origin_url") or "",
                "action_url": col(row, "action_url"),
                "username_element": col(row, "username_element"),
                "username_value": col(row, "username_value") or "",
                "signon_realm": col(row, "signon_realm"),
                "times_used": to_int(col(row, "times_used"), 0),
                "blacklisted": bool(to_int(col(row, "blacklisted_by_user"), 0)),
                "has_password": bool(col(row, "password_value")),
            }
            msg = f"Login for {attrs['username_value']} at {attrs['origin_url']} (used {attrs['times_used']} times)"
            rid = to_int(col(row, "rid"), idx) or idx
            emitted = False
            for column, desc in (("date_created", Desc.CREATION), ("date_last_used", "Last Used Time"),
                                 ("date_password_modified", Desc.MODIFICATION), ("date_synced", "Synced Time")):
                ts = _ws(col(row, column))
                if ts is not None:
                    emitted = True
                    yield parser.event("chrome:login_data:entry", desc, msg, ts, offset=rid, attrs=attrs)
            if not emitted:
                yield parser.event("chrome:login_data:entry", Desc.NOT_A_TIME, msg, None, offset=rid, attrs=attrs)
        except Exception as exc:  # noqa: BLE001
            parser.warn(f"logins row {idx}: {exc}")


class ChromiumWebDataParser(BaseParser):
    """``Web Data``: autofill entries, keywords (search engines) and, if present, logins."""

    name = "chromium_webdata"
    version = "1.0"
    source_short = "WEBHIST"
    source_long = "Chrome Autofill"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return is_sqlite(head_bytes) and pathlib.Path(path).name.lower() in ("web data", "web data.db", "webdata")

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            found = False
            if has_table(conn, "autofill"):
                found = True
                yield from self._autofill(conn)
            if has_table(conn, "keywords"):
                found = True
                yield from self._keywords(conn)
            if has_table(conn, "logins"):
                found = True
                yield from _logins(self, conn)
            if not found:
                raise ParserError("chromium_webdata: no autofill/keywords/logins table")

    def _autofill(self, conn) -> Iterator[Event]:
        acols = columns(conn, "autofill")
        if "date_created" in acols:
            sql = "SELECT rowid AS rid, name, value, date_created, date_last_used, count FROM autofill ORDER BY rowid"
        elif has_table(conn, "autofill_dates"):  # pre-2014 schema
            sql = ("SELECT autofill.rowid AS rid, autofill.name, autofill.value, autofill_dates.date_created AS date_created, "
                   "NULL AS date_last_used, autofill.count FROM autofill JOIN autofill_dates "
                   "ON autofill.pair_id = autofill_dates.pair_id ORDER BY autofill.rowid")
        else:
            return
        for idx, row in enumerate(rows(conn, sql), 1):
            try:
                attrs = {
                    "field_name": col(row, "name") or "",
                    "value": col(row, "value") or "",
                    "usage_count": to_int(col(row, "count"), 0),
                }
                msg = (f"Form field name: {attrs['field_name']} Entered value: {attrs['value']} "
                       f"Times used: {attrs['usage_count']}")
                rid = to_int(col(row, "rid"), idx) or idx
                created = to_int(col(row, "date_created"))
                if created:
                    yield self.event("chrome:autofill:entry", Desc.CREATION, msg, unix_to_ns(created), offset=rid, attrs=attrs)
                used = to_int(col(row, "date_last_used"))
                if used:
                    yield self.event("chrome:autofill:entry", "Last Used Time", msg, unix_to_ns(used), offset=rid, attrs=attrs)
                if not created and not used:
                    yield self.event("chrome:autofill:entry", Desc.NOT_A_TIME, msg, None, offset=rid, attrs=attrs)
            except Exception as exc:  # noqa: BLE001
                self.warn(f"autofill row {idx}: {exc}")

    def _keywords(self, conn) -> Iterator[Event]:
        kcols = columns(conn, "keywords")
        for idx, row in enumerate(rows(conn, "SELECT * FROM keywords ORDER BY id"), 1):
            try:
                attrs = {
                    "short_name": col(row, "short_name") or "",
                    "keyword": col(row, "keyword") or "",
                    "url": col(row, "url") or "",
                    "usage_count": to_int(col(row, "usage_count"), 0),
                    "created_by_policy": bool(to_int(col(row, "created_by_policy"), 0)),
                }
                msg = f"Search engine: {attrs['short_name']} ({attrs['keyword']}) {attrs['url']}"
                kid = to_int(col(row, "id"), idx) or idx
                emitted = False
                for column, desc in (("date_created", Desc.CREATION), ("last_modified", Desc.MODIFICATION),
                                     ("last_visited", Desc.LAST_VISITED)):
                    if column not in kcols:
                        continue
                    v = to_int(col(row, column))
                    if not v:
                        continue
                    # date_created is unix seconds in old schemas and WebKit us in new ones.
                    ts = _ws(v) if v > 10_000_000_000 else unix_to_ns(v)
                    emitted = True
                    yield self.event("chrome:webdata:keyword", desc, msg, ts, offset=kid, attrs=attrs)
                if not emitted:
                    yield self.event("chrome:webdata:keyword", Desc.NOT_A_TIME, msg, None, offset=kid, attrs=attrs)
            except Exception as exc:  # noqa: BLE001
                self.warn(f"keywords row {idx}: {exc}")


class ChromiumLoginDataParser(BaseParser):
    name = "chromium_login_data"
    version = "1.0"
    source_short = "WEBHIST"
    source_long = "Chrome Login Data"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return is_sqlite(head_bytes) and pathlib.Path(path).name.lower() in ("login data", "login data for account")

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            if not has_table(conn, "logins"):
                raise ParserError("chromium_login_data: no logins table")
            yield from _logins(self, conn)


PARSERS = [ChromiumHistoryParser, ChromiumCookiesParser, ChromiumWebDataParser, ChromiumLoginDataParser]


def parse(path: str, provenance: Provenance | None = None) -> Iterator[Event]:
    """Parse ``path`` with whichever parser in this module matches its name and header.

    Raises ``ParserError`` when none matches.
    """
    from veritas.parsers.base import read_head

    head = read_head(path)
    for cls in PARSERS:
        parser = cls()
        if parser.matches(path, head):
            yield from parser.parse(path, provenance or Provenance())
            return
    raise ParserError(f"{__name__}: no parser matches {path}")
