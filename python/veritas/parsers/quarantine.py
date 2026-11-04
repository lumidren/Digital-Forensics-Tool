"""macOS LaunchServices quarantine events (``com.apple.LaunchServices.QuarantineEventsV2``).

``LSQuarantineEvent``: LSQuarantineTimeStamp (Cocoa seconds) -> ``macos:lsquarantine:entry``
("Downloaded Time", plaso vocabulary) with agent name/bundle, data URL, origin URL/title, sender.
"""
from __future__ import annotations

import pathlib
from typing import Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance, cocoa_to_ns
from veritas.parsers.sqlite_safe import col, has_table, is_sqlite, open_sqlite, rows, to_int
from veritas.timeline.schema import Event

DOWNLOADED = "Downloaded Time"


class QuarantineParser(BaseParser):
    name = "ls_quarantine"
    version = "1.0"
    source_short = "LOG"
    source_long = "LS Quarantine Event"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        n = pathlib.Path(path).name.lower()
        return is_sqlite(head_bytes) and ("quarantine" in n)

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            if not has_table(conn, "LSQuarantineEvent"):
                raise ParserError("ls_quarantine: no LSQuarantineEvent table")
            for idx, row in enumerate(rows(conn, "SELECT rowid AS rid, * FROM LSQuarantineEvent ORDER BY rowid"), 1):
                try:
                    attrs = {
                        "identifier": col(row, "LSQuarantineEventIdentifier"), "agent": col(row, "LSQuarantineAgentName"),
                        "agent_bundle_identifier": col(row, "LSQuarantineAgentBundleIdentifier"),
                        "data": col(row, "LSQuarantineDataURLString"), "url": col(row, "LSQuarantineOriginURLString"),
                        "origin_title": col(row, "LSQuarantineOriginTitle"), "sender_name": col(row, "LSQuarantineSenderName"),
                        "sender_address": col(row, "LSQuarantineSenderAddress"), "type_number": to_int(col(row, "LSQuarantineTypeNumber")),
                    }
                    msg = f"[{attrs['agent']}] Downloaded: {attrs['data']} <{attrs['url']}>"
                    yield self.event("macos:lsquarantine:entry", DOWNLOADED, msg, cocoa_to_ns(col(row, "LSQuarantineTimeStamp")),
                                     offset=to_int(col(row, "rid"), idx) or idx, attrs=attrs)
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"row {idx}: {exc}")


PARSERS = [QuarantineParser]
