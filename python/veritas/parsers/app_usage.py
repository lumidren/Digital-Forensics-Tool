"""macOS ``application_usage.sqlite`` (``/var/db/application_usage.sqlite``, pre-10.10).

``application_usage``: event (launch/...), bundle_id, app_version, app_path, last_time (Unix
seconds), number_times -> ``macos:application_usage:entry`` (Last Used Time).
"""
from __future__ import annotations

import pathlib
from typing import Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.parsers.sqlite_safe import col, has_table, is_sqlite, open_sqlite, rows, to_int
from veritas.timeline.schema import NS, Event


class AppUsageParser(BaseParser):
    name = "macos_appusage"
    version = "1.0"
    source_short = "LOG"
    source_long = "Application Usage"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return is_sqlite(head_bytes) and pathlib.Path(path).name.lower() == "application_usage.sqlite"

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            if not has_table(conn, "application_usage"):
                raise ParserError("macos_appusage: no application_usage table")
            for idx, row in enumerate(rows(conn, "SELECT rowid AS rid, * FROM application_usage ORDER BY rowid"), 1):
                try:
                    attrs = {"application": col(row, "app_path"), "bundle_identifier": col(row, "bundle_id"),
                             "app_version": col(row, "app_version"), "event": col(row, "event"),
                             "count": to_int(col(row, "number_times"))}
                    lt = to_int(col(row, "last_time"))
                    msg = f"{attrs['application']} v.{attrs['app_version']} (bundle: {attrs['bundle_identifier']}). Launched: {attrs['count']} time(s)"
                    yield self.event("macos:application_usage:entry", "Last Used Time", msg, lt * NS if lt else None,
                                     offset=to_int(col(row, "rid"), idx) or idx, attrs=attrs)
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"row {idx}: {exc}")


PARSERS = [AppUsageParser]
