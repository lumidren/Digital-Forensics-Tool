"""Windows 10 Timeline (``ActivitiesCache.db``).

``Activity`` rows: ``AppId`` is a JSON list of ``{application, platform}``; ``Payload`` a JSON
object (``displayText``, ``description``, ``contentUri``, ``appDisplayName``, and for
``ActivityType`` 6 ``type: UserEngaged`` + ``activeDurationSeconds``). Times are Unix seconds.

ActivityType 5 -> ``windows:timeline:generic``; 6 -> ``windows:timeline:user_engaged``;
others -> ``windows:timeline:activity``. Events: StartTime (Start Time), EndTime (End Time),
LastModifiedTime (Content Modification Time), ExpirationTime (Expiration Time).
``ActivityOperation`` rows (pending uploads) are emitted the same way with
``attrs.table = 'ActivityOperation'``.
"""
from __future__ import annotations

import json
import pathlib
from typing import Any, Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.parsers.sqlite_safe import col, columns, has_table, is_sqlite, open_sqlite, rows, to_int
from veritas.timeline.schema import NS, Desc, Event

TYPES = {5: "windows:timeline:generic", 6: "windows:timeline:user_engaged"}
TIMES = (("StartTime", Desc.START), ("EndTime", Desc.END), ("LastModifiedTime", Desc.MODIFICATION),
         ("ExpirationTime", Desc.EXPIRATION))


def _json(text: Any) -> Any:
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


class WindowsTimelineParser(BaseParser):
    name = "windows_timeline"
    version = "1.0"
    source_short = "LOG"
    source_long = "Windows Timeline"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return is_sqlite(head_bytes) and pathlib.Path(path).name.lower() == "activitiescache.db"

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            if not has_table(conn, "Activity"):
                raise ParserError("windows_timeline: no Activity table")
            for table in ("Activity", "ActivityOperation"):
                if not has_table(conn, table):
                    continue
                cols = columns(conn, table)
                order = "ETag" if "ETag" in cols else "rowid"
                for idx, row in enumerate(rows(conn, f'SELECT rowid AS rid, * FROM "{table}" ORDER BY {order}, rowid'), 1):
                    try:
                        yield from self._row(table, idx, row)
                    except Exception as exc:  # noqa: BLE001
                        self.warn(f"{table} row {idx}: {exc}")

    def _row(self, table: str, idx: int, row) -> Iterator[Event]:
        atype = to_int(col(row, "ActivityType"), 0) or 0
        apps = _json(col(row, "AppId")) or []
        app_name = ""
        package = None
        if isinstance(apps, list):
            for a in apps:
                if not isinstance(a, dict):
                    continue
                if a.get("platform") in ("windows_win32", "windows_universal", "x_exe_path") and not app_name:
                    app_name = str(a.get("application", ""))
                if a.get("platform") == "packageId":
                    package = a.get("application")
            if not app_name and apps and isinstance(apps[0], dict):
                app_name = str(apps[0].get("application", ""))
        payload = _json(col(row, "Payload")) or {}
        if not isinstance(payload, dict):
            payload = {}
        attrs = {
            "table": table, "activity_type": atype, "application": app_name, "package_identifier": package,
            "display_text": payload.get("displayText"), "description": payload.get("description"),
            "content_uri": payload.get("contentUri"), "app_display_name": payload.get("appDisplayName"),
            "active_duration_seconds": to_int(payload.get("activeDurationSeconds")),
            "reporting_app": payload.get("reportingApp"), "user_timezone": payload.get("userTimezone"),
            "platform_device_identifier": col(row, "PlatformDeviceId"), "app_activity_identifier": col(row, "AppActivityId"),
            "activity_status": to_int(col(row, "ActivityStatus")), "etag": to_int(col(row, "ETag")),
        }
        dtype = TYPES.get(atype, "windows:timeline:activity")
        label = attrs["display_text"] or attrs["app_display_name"] or app_name
        msg = f"{app_name} {label or ''}".strip()
        if atype == 6:
            msg = f"Application: {app_name} Active duration (seconds): {attrs['active_duration_seconds']}"
        oid = to_int(col(row, "rid"), idx) or idx
        emitted = False
        for column, desc in TIMES:
            v = to_int(col(row, column))
            if v and v > 0:
                emitted = True
                yield self.event(dtype, desc, msg, v * NS, offset=oid, attrs=attrs)
        if not emitted:
            yield self.event(dtype, Desc.NOT_A_TIME, msg, None, offset=oid, attrs=attrs)


PARSERS = [WindowsTimelineParser]
