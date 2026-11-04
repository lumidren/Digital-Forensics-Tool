"""Firefox profile databases: places.sqlite, downloads.sqlite (legacy), cookies.sqlite.

* ``moz_places`` / ``moz_historyvisits``: page visits (``firefox:places:page_visited``).
* ``moz_bookmarks`` + ``moz_items_annos``: bookmarks, folders, annotations.
* ``moz_annos`` ``downloads/destinationFileURI`` + ``downloads/metaData`` (Firefox >= 26
  stores downloads as place annotations) -> ``firefox:downloads:download``.
* ``moz_downloads`` in the legacy ``downloads.sqlite`` -> ``firefox:downloads:download``.
* ``moz_cookies`` -> ``firefox:cookie:entry``.

All Firefox timestamps are Unix microseconds except ``moz_cookies.expiry`` (seconds) and the
``endTime`` inside the downloads JSON (milliseconds).
"""
from __future__ import annotations

import json
import pathlib
from typing import Any, Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.parsers.sqlite_safe import col, columns, has_table, is_sqlite, open_sqlite, rows, to_int
from veritas.timeline.schema import NS, Desc, Event

VISIT_TYPES = {
    1: "LINK", 2: "TYPED", 3: "BOOKMARK", 4: "EMBED", 5: "REDIRECT_PERMANENT", 6: "REDIRECT_TEMPORARY",
    7: "DOWNLOAD", 8: "FRAMED_LINK", 9: "RELOAD",
}
BOOKMARK_TYPES = {1: "URL", 2: "Folder", 3: "Separator"}
DOWNLOAD_STATES = {
    -1: "NOTSTARTED", 0: "DOWNLOADING", 1: "FINISHED", 2: "FAILED", 3: "CANCELED", 4: "PAUSED", 5: "QUEUED",
    6: "BLOCKED_PARENTAL", 7: "SCANNING", 8: "DIRTY", 9: "BLOCKED_POLICY",
}


def _us(value: Any) -> int | None:
    v = to_int(value)
    if not v or v < 0:
        return None
    return v * 1000


class FirefoxPlacesParser(BaseParser):
    name = "firefox_places"
    version = "1.0"
    source_short = "WEBHIST"
    source_long = "Firefox History"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return is_sqlite(head_bytes) and pathlib.Path(path).name.lower().startswith("places")

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            if not has_table(conn, "moz_places"):
                raise ParserError("firefox_places: no moz_places table")
            if has_table(conn, "moz_historyvisits"):
                yield from self._visits(conn)
            if has_table(conn, "moz_bookmarks"):
                yield from self._bookmarks(conn)
            if has_table(conn, "moz_items_annos"):
                yield from self._bookmark_annotations(conn)
            if has_table(conn, "moz_annos") and has_table(conn, "moz_anno_attributes"):
                yield from self._download_annotations(conn)

    def _visits(self, conn) -> Iterator[Event]:
        sql = ("SELECT v.id AS visit_id, v.from_visit, v.visit_date, v.visit_type, p.id AS place_id, p.url, p.title, "
               "p.rev_host, p.visit_count, p.hidden, p.typed FROM moz_historyvisits v JOIN moz_places p "
               "ON v.place_id = p.id ORDER BY v.id")
        for row in rows(conn, sql):
            try:
                vtype = to_int(col(row, "visit_type"), 0) or 0
                url = col(row, "url") or ""
                title = col(row, "title") or ""
                rev_host = col(row, "rev_host") or ""
                attrs = {
                    "url": url, "title": title, "host": rev_host[::-1].lstrip("."),
                    "visit_id": to_int(col(row, "visit_id")), "place_id": to_int(col(row, "place_id")),
                    "from_visit": to_int(col(row, "from_visit"), 0), "visit_type": vtype,
                    "visit_type_name": VISIT_TYPES.get(vtype, "UNKNOWN"),
                    "visit_count": to_int(col(row, "visit_count"), 0), "typed": bool(to_int(col(row, "typed"), 0)),
                    "hidden": bool(to_int(col(row, "hidden"), 0)),
                }
                msg = f"{url} ({title})" if title else url
                msg += f" [count: {attrs['visit_count']}]"
                if attrs["typed"]:
                    msg += " (URL directly typed)"
                msg += f" Transition: {attrs['visit_type_name']}"
                yield self.event("firefox:places:page_visited", Desc.LAST_VISITED, msg, _us(col(row, "visit_date")),
                                 offset=int(attrs["visit_id"] or 0), attrs=attrs)
            except Exception as exc:  # noqa: BLE001
                self.warn(f"moz_historyvisits row: {exc}")

    def _bookmarks(self, conn) -> Iterator[Event]:
        sql = ("SELECT b.id, b.type, b.fk, b.parent, b.position, b.title, b.dateAdded, b.lastModified, p.url, p.visit_count "
               "FROM moz_bookmarks b LEFT JOIN moz_places p ON b.fk = p.id ORDER BY b.id")
        for row in rows(conn, sql):
            try:
                btype = to_int(col(row, "type"), 0) or 0
                attrs = {
                    "bookmark_id": to_int(col(row, "id")), "type": btype, "type_name": BOOKMARK_TYPES.get(btype, "UNKNOWN"),
                    "title": col(row, "title") or "", "url": col(row, "url"), "parent": to_int(col(row, "parent")),
                    "position": to_int(col(row, "position")), "places_id": to_int(col(row, "fk")),
                    "visit_count": to_int(col(row, "visit_count")),
                }
                if btype == 2:
                    dtype = "firefox:places:bookmark_folder"
                    msg = attrs["title"] or "(unnamed folder)"
                else:
                    dtype = "firefox:places:bookmark"
                    msg = f"Bookmark {attrs['type_name']} {attrs['title']} ({attrs['url'] or ''}) [{attrs['visit_count'] or 0}]"
                oid = attrs["bookmark_id"] or 0
                added = _us(col(row, "dateAdded"))
                modified = _us(col(row, "lastModified"))
                if added is not None:
                    yield self.event(dtype, "Added Time", msg, added, offset=int(oid), attrs=attrs)
                if modified is not None:
                    yield self.event(dtype, Desc.MODIFICATION, msg, modified, offset=int(oid), attrs=attrs)
                if added is None and modified is None:
                    yield self.event(dtype, Desc.NOT_A_TIME, msg, None, offset=int(oid), attrs=attrs)
            except Exception as exc:  # noqa: BLE001
                self.warn(f"moz_bookmarks row: {exc}")

    def _bookmark_annotations(self, conn) -> Iterator[Event]:
        sql = ("SELECT a.id, a.item_id, n.name, a.content, a.dateAdded, a.lastModified, b.title, p.url "
               "FROM moz_items_annos a JOIN moz_anno_attributes n ON a.anno_attribute_id = n.id "
               "LEFT JOIN moz_bookmarks b ON a.item_id = b.id LEFT JOIN moz_places p ON b.fk = p.id ORDER BY a.id")
        for row in rows(conn, sql):
            try:
                attrs = {
                    "annotation_id": to_int(col(row, "id")), "item_id": to_int(col(row, "item_id")),
                    "name": col(row, "name") or "", "content": col(row, "content") or "",
                    "title": col(row, "title") or "", "url": col(row, "url"),
                }
                msg = f"Bookmark Annotation: [{attrs['content']}] to bookmark [{attrs['title']}] ({attrs['url'] or ''})"
                oid = attrs["annotation_id"] or 0
                added = _us(col(row, "dateAdded"))
                modified = _us(col(row, "lastModified"))
                if added is not None:
                    yield self.event("firefox:places:bookmark_annotation", "Added Time", msg, added, offset=int(oid), attrs=attrs)
                if modified is not None:
                    yield self.event("firefox:places:bookmark_annotation", Desc.MODIFICATION, msg, modified, offset=int(oid), attrs=attrs)
            except Exception as exc:  # noqa: BLE001
                self.warn(f"moz_items_annos row: {exc}")

    def _download_annotations(self, conn) -> Iterator[Event]:
        sql = ("SELECT a.id, a.place_id, n.name, a.content, a.dateAdded, p.url FROM moz_annos a "
               "JOIN moz_anno_attributes n ON a.anno_attribute_id = n.id LEFT JOIN moz_places p ON a.place_id = p.id "
               "WHERE n.name IN ('downloads/destinationFileURI', 'downloads/metaData') ORDER BY a.place_id, a.id")
        per_place: dict[int, dict[str, Any]] = {}
        order: list[int] = []
        for row in rows(conn, sql):
            try:
                pid = to_int(col(row, "place_id"), 0) or 0
                entry = per_place.setdefault(pid, {"url": col(row, "url") or "", "offset": to_int(col(row, "id"), 0)})
                if pid not in order:
                    order.append(pid)
                name = col(row, "name")
                if name == "downloads/destinationFileURI":
                    entry["target"] = col(row, "content") or ""
                    entry["start"] = _us(col(row, "dateAdded"))
                else:
                    try:
                        meta = json.loads(col(row, "content") or "{}")
                    except ValueError:
                        meta = {}
                    if not isinstance(meta, dict):
                        meta = {}
                    entry["meta"] = meta
                    entry["meta_added"] = _us(col(row, "dateAdded"))
            except Exception as exc:  # noqa: BLE001
                self.warn(f"moz_annos row: {exc}")
        for pid in order:
            e = per_place[pid]
            meta = e.get("meta", {})
            state = to_int(meta.get("state"))
            end_ms = to_int(meta.get("endTime"))
            attrs = {
                "url": e["url"], "full_path": e.get("target", ""), "place_id": pid,
                "state": state, "state_name": DOWNLOAD_STATES.get(state, "UNKNOWN") if state is not None else None,
                "received_bytes": to_int(meta.get("fileSize")), "total_bytes": to_int(meta.get("fileSize")),
                "deleted": bool(meta.get("deleted", False)),
            }
            msg = f"{attrs['url']} ({attrs['full_path']}). Received: {attrs['received_bytes'] or 0} bytes"
            start = e.get("start")
            if start is not None:
                yield self.event("firefox:downloads:download", Desc.START, msg, start, offset=e["offset"], attrs=attrs)
            if end_ms:
                yield self.event("firefox:downloads:download", Desc.END, msg, end_ms * 1_000_000, offset=e["offset"], attrs=attrs)
            if start is None and not end_ms:
                yield self.event("firefox:downloads:download", Desc.NOT_A_TIME, msg, None, offset=e["offset"], attrs=attrs)


class FirefoxDownloadsParser(BaseParser):
    """Legacy ``downloads.sqlite`` (Firefox < 26)."""

    name = "firefox_downloads"
    version = "1.0"
    source_short = "WEBHIST"
    source_long = "Firefox Downloads"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return is_sqlite(head_bytes) and pathlib.Path(path).name.lower() == "downloads.sqlite"

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            if not has_table(conn, "moz_downloads"):
                raise ParserError("firefox_downloads: no moz_downloads table")
            for row in rows(conn, "SELECT * FROM moz_downloads ORDER BY id"):
                try:
                    state = to_int(col(row, "state"))
                    attrs = {
                        "download_id": to_int(col(row, "id")), "name": col(row, "name") or "",
                        "url": col(row, "source") or "", "full_path": col(row, "target") or "",
                        "temporary_location": col(row, "tempPath"), "referrer": col(row, "referrer"),
                        "received_bytes": to_int(col(row, "currBytes"), 0), "total_bytes": to_int(col(row, "maxBytes"), 0),
                        "mime_type": col(row, "mimeType"), "state": state,
                        "state_name": DOWNLOAD_STATES.get(state, "UNKNOWN") if state is not None else None,
                    }
                    msg = (f"{attrs['url']} ({attrs['full_path']}). Received: {attrs['received_bytes']} bytes "
                           f"out of: {attrs['total_bytes']} bytes.")
                    oid = attrs["download_id"] or 0
                    start = _us(col(row, "startTime"))
                    end = _us(col(row, "endTime"))
                    if start is not None:
                        yield self.event("firefox:downloads:download", Desc.START, msg, start, offset=int(oid), attrs=attrs)
                    if end is not None:
                        yield self.event("firefox:downloads:download", Desc.END, msg, end, offset=int(oid), attrs=attrs)
                    if start is None and end is None:
                        yield self.event("firefox:downloads:download", Desc.NOT_A_TIME, msg, None, offset=int(oid), attrs=attrs)
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"moz_downloads row: {exc}")


class FirefoxCookiesParser(BaseParser):
    name = "firefox_cookies"
    version = "1.0"
    source_short = "WEBHIST"
    source_long = "Firefox Cookies"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        base = pathlib.Path(path).name.lower()
        return is_sqlite(head_bytes) and "cookies" in base and base.endswith(".sqlite")

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            if not has_table(conn, "moz_cookies"):
                raise ParserError("firefox_cookies: no moz_cookies table")
            ccols = columns(conn, "moz_cookies")
            for row in rows(conn, "SELECT * FROM moz_cookies ORDER BY id"):
                try:
                    host = col(row, "host") or col(row, "baseDomain") or ""
                    path_ = col(row, "path") or "/"
                    secure = bool(to_int(col(row, "isSecure"), 0))
                    attrs = {
                        "cookie_id": to_int(col(row, "id")), "host": host, "cookie_name": col(row, "name") or "",
                        "data": col(row, "value") or "", "path": path_, "secure": secure,
                        "httponly": bool(to_int(col(row, "isHttpOnly"), 0)),
                        "samesite": to_int(col(row, "sameSite")) if "sameSite" in ccols else None,
                        "url": ("https://" if secure else "http://") + host.lstrip(".") + path_,
                    }
                    msg = (f"{attrs['url']} ({attrs['cookie_name']}) Flags: [HTTP only] = {attrs['httponly']} "
                           f"[Secure] = {secure}")
                    oid = attrs["cookie_id"] or 0
                    creation = _us(col(row, "creationTime"))
                    accessed = _us(col(row, "lastAccessed"))
                    expiry = to_int(col(row, "expiry"))
                    if creation is not None:
                        yield self.event("firefox:cookie:entry", Desc.CREATION, msg, creation, offset=int(oid), attrs=attrs)
                    if accessed is not None:
                        yield self.event("firefox:cookie:entry", Desc.ACCESS, msg, accessed, offset=int(oid), attrs=attrs)
                    if expiry:
                        yield self.event("firefox:cookie:entry", Desc.EXPIRATION, msg, expiry * NS, offset=int(oid), attrs=attrs)
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"moz_cookies row: {exc}")


PARSERS = [FirefoxPlacesParser, FirefoxDownloadsParser, FirefoxCookiesParser]


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
