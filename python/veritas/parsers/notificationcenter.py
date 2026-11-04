"""macOS Notification Center database (``db`` under ``com.apple.notificationcenter``).

``record`` joined to ``app`` (app_id -> bundle identifier). The ``data`` column is a binary
plist (``{app, req: {titl, subt, body, ...}, date, ...}``) decoded with ``plistlib`` (capped at
1 MiB). ``delivered_date`` (Cocoa seconds) -> ``macos:notification_center:entry`` (Creation Time,
plaso vocabulary); ``request_date`` / ``request_last_date`` / ``snooze_fire_date`` become extra
events when present.
"""
from __future__ import annotations

import plistlib
from typing import Any, Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance, clip, cocoa_to_ns
from veritas.parsers.sqlite_safe import col, has_table, is_sqlite, open_sqlite, rows, to_int
from veritas.timeline.schema import Desc, Event

MAX_PLIST = 1024 * 1024


def _decode(blob: Any) -> dict:
    if not isinstance(blob, (bytes, bytearray)) or len(blob) > MAX_PLIST:
        return {}
    try:
        obj = plistlib.loads(bytes(blob))
    except Exception:  # noqa: BLE001 - malformed plist inside evidence
        return {}
    return obj if isinstance(obj, dict) else {}


class NotificationCenterParser(BaseParser):
    name = "macos_notification_center"
    version = "1.0"
    source_short = "LOG"
    source_long = "Notification Center"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        n = path.replace("\\", "/").lower()
        return is_sqlite(head_bytes) and ("notificationcenter" in n or n.rsplit("/", 1)[-1] == "db")

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            if not has_table(conn, "record"):
                raise ParserError("notification_center: no record table")
            join = "LEFT JOIN app ON record.app_id = app.app_id" if has_table(conn, "app") else ""
            ident = "app.identifier AS bundle" if join else "NULL AS bundle"
            sql = f"SELECT record.*, {ident} FROM record {join} ORDER BY record.rec_id"
            for idx, row in enumerate(rows(conn, sql), 1):
                try:
                    plist = _decode(row["data"] if "data" in row.keys() else None)
                    req = plist.get("req") if isinstance(plist.get("req"), dict) else {}
                    attrs = {
                        "bundle_name": col(row, "bundle") or plist.get("app"), "title": clip(req.get("titl")),
                        "subtitle": clip(req.get("subt")), "body": clip(req.get("body")),
                        "presented": bool(to_int(col(row, "presented"), 0)), "style": to_int(col(row, "style")),
                        "record_identifier": to_int(col(row, "rec_id")),
                    }
                    msg = f"Title: {attrs['title']} registered by: {attrs['bundle_name']} Body: {attrs['body']}"
                    rid = attrs["record_identifier"] or idx
                    emitted = False
                    for column, desc in (("delivered_date", Desc.CREATION), ("request_date", "Request Time"),
                                         ("request_last_date", "Last Request Time"), ("snooze_fire_date", "Snooze Fire Time")):
                        ts = cocoa_to_ns(col(row, column))
                        if ts is not None:
                            emitted = True
                            yield self.event("macos:notification_center:entry", desc, msg, ts, offset=rid, attrs=attrs)
                    if not emitted:
                        yield self.event("macos:notification_center:entry", Desc.NOT_A_TIME, msg, None, offset=rid, attrs=attrs)
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"record {idx}: {exc}")


PARSERS = [NotificationCenterParser]
