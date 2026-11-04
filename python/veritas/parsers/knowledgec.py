"""macOS / iOS KnowledgeC (``knowledgeC.db``, CoreDuet).

``ZOBJECT`` rows are joined to ``ZSOURCE`` (bundle id, group id) and ``ZSTRUCTUREDMETADATA``
(stream specific metadata). The schema varies by OS release (10.13 has no ZSTRUCTUREDMETADATA
Safari title column, 10.14 does); every metadata column is selected only when present.

Data types: ``/app/inFocus`` and ``/app/usage`` -> ``macos:knowledgec:application``;
``/safari/history`` -> ``macos:knowledgec:safari``; ``/media/nowPlaying`` -> ``macos:knowledgec:media``;
``/app/activity`` -> ``macos:knowledgec:application`` (as plaso); anything else -> ``macos:knowledgec:entry``.
Times are Cocoa seconds: ZCREATIONDATE (Creation Time), ZSTARTDATE (Start Time), ZENDDATE (End Time);
``attrs.duration_seconds`` = end - start.
"""
from __future__ import annotations

import pathlib
from typing import Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance, cocoa_to_ns
from veritas.parsers.sqlite_safe import col, columns, has_table, is_sqlite, open_sqlite, rows, to_int
from veritas.timeline.schema import Desc, Event

STREAM_TYPES = {
    "/app/inFocus": "macos:knowledgec:application", "/app/usage": "macos:knowledgec:application",
    "/safari/history": "macos:knowledgec:safari", "/media/nowPlaying": "macos:knowledgec:media",
    "/app/activity": "macos:knowledgec:application",  # plaso groups app activity with application events
}
META_COLUMNS = {
    "Z_DKSAFARIHISTORYMETADATAKEY__TITLE": "title",
    "Z_DKNOWPLAYINGMETADATAKEY__TITLE": "media_title", "Z_DKNOWPLAYINGMETADATAKEY__ARTIST": "media_artist",
    "Z_DKNOWPLAYINGMETADATAKEY__ALBUM": "media_album", "Z_DKNOWPLAYINGMETADATAKEY__PLAYING": "media_playing",
    "Z_DKAPPLICATIONACTIVITYMETADATAKEY__ACTIVITYTYPE": "activity_type",
    "Z_DKAPPLICATIONACTIVITYMETADATAKEY__TITLE": "activity_title",
    "Z_DKAPPLICATIONACTIVITYMETADATAKEY__CONTENTDESCRIPTION": "content_description",
    "Z_DKAPPLICATIONACTIVITYMETADATAKEY__ITEMRELATEDCONTENTURL": "content_url",
    "Z_DKAPPLICATIONMETADATAKEY__LAUNCHREASON": "launch_reason",
}


class KnowledgeCParser(BaseParser):
    name = "knowledgec"
    version = "1.0"
    source_short = "LOG"
    source_long = "KnowledgeC"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        n = pathlib.Path(path).name.lower()
        return is_sqlite(head_bytes) and "knowledgec" in n

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            if not has_table(conn, "ZOBJECT"):
                raise ParserError("knowledgec: no ZOBJECT table")
            ocols = set(columns(conn, "ZOBJECT"))
            select = ["o.Z_PK AS pk", "o.ZSTREAMNAME AS stream", "o.ZVALUESTRING AS value",
                      "o.ZSTARTDATE AS start", "o.ZENDDATE AS end_", "o.ZCREATIONDATE AS created",
                      "o.ZSECONDSFROMGMT AS gmt_offset" if "ZSECONDSFROMGMT" in ocols else "NULL AS gmt_offset",
                      "o.ZUUID AS uuid" if "ZUUID" in ocols else "NULL AS uuid"]
            joins = []
            if has_table(conn, "ZSOURCE") and "ZSOURCE" in ocols:
                scols = set(columns(conn, "ZSOURCE"))
                joins.append("LEFT JOIN ZSOURCE s ON o.ZSOURCE = s.Z_PK")
                select.append("s.ZBUNDLEID AS source_bundle" if "ZBUNDLEID" in scols else "NULL AS source_bundle")
                select.append("s.ZGROUPID AS source_group" if "ZGROUPID" in scols else "NULL AS source_group")
            meta_keys: dict[str, str] = {}
            if has_table(conn, "ZSTRUCTUREDMETADATA") and "ZSTRUCTUREDMETADATA" in ocols:
                mcols = set(columns(conn, "ZSTRUCTUREDMETADATA"))
                joins.append("LEFT JOIN ZSTRUCTUREDMETADATA m ON o.ZSTRUCTUREDMETADATA = m.Z_PK")
                for c, alias in META_COLUMNS.items():
                    if c in mcols:
                        select.append(f"m.{c} AS meta_{alias}")
                        meta_keys[alias] = f"meta_{alias}"
            sql = f"SELECT {', '.join(select)} FROM ZOBJECT o {' '.join(joins)} ORDER BY o.Z_PK"  # nosec B608 - columns come from the constant META_COLUMNS map
            for row in rows(conn, sql):
                try:
                    yield from self._row(row, meta_keys)
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"ZOBJECT {col(row, 'pk')}: {exc}")

    def _row(self, row, meta_keys: dict[str, str]) -> Iterator[Event]:
        stream = col(row, "stream") or ""
        dtype = STREAM_TYPES.get(stream, "macos:knowledgec:entry")
        start, end, created = cocoa_to_ns(col(row, "start")), cocoa_to_ns(col(row, "end_")), cocoa_to_ns(col(row, "created"))
        attrs = {"stream_name": stream, "value": col(row, "value"), "uuid": col(row, "uuid"),
                 "gmt_offset_seconds": to_int(col(row, "gmt_offset")), "source_bundle_identifier": col(row, "source_bundle"),
                 "source_group_identifier": col(row, "source_group"),
                 "duration_seconds": (end - start) // 1_000_000_000 if start is not None and end is not None else None}
        for alias, key in meta_keys.items():
            v = col(row, key)
            if v is not None:
                attrs[alias] = v if not isinstance(v, float) else int(v)
        if dtype == "macos:knowledgec:safari":
            attrs["url"] = attrs["value"]
            msg = f"Safari visit {attrs.get('title') or ''} {attrs['url']}".strip()
        elif dtype == "macos:knowledgec:application":
            attrs["bundle_identifier"] = attrs["value"]
            msg = f"Application {attrs['value']} {stream} duration {attrs['duration_seconds']}s"
        else:
            msg = f"{stream} {attrs['value'] or attrs.get('media_title') or ''}".strip()
        pk = to_int(col(row, "pk"), 0) or 0
        emitted = False
        for ts, desc in ((created, Desc.CREATION), (start, Desc.START), (end, Desc.END)):
            if ts is not None:
                emitted = True
                yield self.event(dtype, desc, msg, ts, offset=pk, attrs=attrs)
        if not emitted:
            yield self.event(dtype, Desc.NOT_A_TIME, msg, None, offset=pk, attrs=attrs)


PARSERS = [KnowledgeCParser]
