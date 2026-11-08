"""Helpers shared by the iOS and Android parsers.

SQLite evidence is always loaded into an in-memory database via ``sqlite3.Connection.deserialize``
so that parsing never writes ``-journal``/``-wal``/``-shm`` files next to evidence and never takes
file locks. Plists are read with :mod:`plistlib` (XML and binary).
"""
from __future__ import annotations

import calendar
import math
import plistlib
import sqlite3
import xml.parsers.expat
from datetime import datetime, timezone
from typing import Any, Iterator

from veritas.cloud.base import ParserError, ParseResult, guard, is_path, make_event, source_name
from veritas.timeline.schema import COCOA_EPOCH_OFFSET_S, NS

__all__ = [
    "ParserError", "ParseResult", "guard", "make_event", "source_name",
    "open_sqlite", "tables", "columns", "query", "load_plist", "dt_to_ns", "cocoa_to_ns", "ms_to_ns",
    "s_to_ns", "ios_message_date_to_ns", "round6", "ADDED", "src_path",
]

ADDED = "Added Time"
SQLITE_MAGIC = b"SQLite format 3\x00"
MAX_DB_BYTES = 2 * 1024 * 1024 * 1024
MAX_PLIST_BYTES = 64 * 1024 * 1024
# Bound for plausible timestamps (year 1900 .. 2200) to reject garbage values.
_MIN_NS = -2_208_988_800 * NS
_MAX_NS = 7_258_118_400 * NS


def src_path(source: Any, evidence_path: str) -> str:
    return evidence_path or source_name(source)


def _raw(source: Any, limit: int) -> bytes:
    if is_path(source):
        data = _read_file(source, limit)
    elif isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    else:
        raise ParserError(f"unsupported source type {type(source).__name__}")
    if len(data) > limit:
        raise ParserError(f"file larger than {limit} bytes")
    return data


def _read_file(path: Any, limit: int) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit + 1)
    except OSError as exc:
        raise ParserError(f"cannot read {source_name(path)}: {exc}") from exc


def open_sqlite(source: Any) -> sqlite3.Connection:
    """Open a SQLite database (path or bytes) as a private in-memory copy."""
    data = _raw(source, MAX_DB_BYTES)
    if not data.startswith(SQLITE_MAGIC) or len(data) < 512:
        raise ParserError("not a SQLite 3 database")
    if data[18:20] == b"\x02\x02":
        # WAL-mode header: switch to rollback journal so the in-memory copy is readable.
        data = data[:18] + b"\x01\x01" + data[20:]
    conn = sqlite3.connect(":memory:")
    try:
        conn.deserialize(data)
        conn.execute("PRAGMA query_only = ON")
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except (sqlite3.Error, OverflowError, ValueError) as exc:
        conn.close()
        raise ParserError(f"unreadable SQLite database: {exc}") from exc
    conn.row_factory = sqlite3.Row
    return conn


def tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")}


def columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')}  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query - sqlite3 PRAGMA on a name validated against sqlite_master


def query(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> Iterator[sqlite3.Row]:
    yield from conn.execute(sql, params)


def col(row: sqlite3.Row, name: str, default: Any = None) -> Any:
    try:
        return row[name]
    except (IndexError, KeyError):
        return default


def load_plist(source: Any) -> Any:
    data = _raw(source, MAX_PLIST_BYTES)
    if not data:
        raise ParserError("empty plist")
    if b"<!ENTITY" in data[:4096]:
        raise ParserError("plist with DTD entity declarations refused")
    try:
        return plistlib.loads(data)
    except (plistlib.InvalidFileException, xml.parsers.expat.ExpatError, ValueError, TypeError, KeyError,
            IndexError, OverflowError, RecursionError, UnicodeDecodeError, AttributeError) as exc:
        raise ParserError(f"invalid plist: {exc}") from exc


def _bounded(ns: int | None) -> int | None:
    if ns is None or ns < _MIN_NS or ns > _MAX_NS:
        return None
    return ns


def dt_to_ns(dt: Any) -> int | None:
    """plistlib datetimes are naive UTC."""
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return _bounded(calendar.timegm(dt.timetuple()) * NS + dt.microsecond * 1000)


def _num(value: Any) -> float | int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        return value
    if isinstance(value, str):
        try:
            v = float(value)
        except ValueError:
            return None
        return v if math.isfinite(v) else None
    return None


def cocoa_to_ns(value: Any) -> int | None:
    """Seconds since 2001-01-01 (float allowed); 0 / None means unset."""
    v = _num(value)
    if not v:
        return None
    if isinstance(v, float):
        whole = math.floor(v)
        frac_ns = int(round((v - whole) * 1_000_000)) * 1000  # microsecond precision, deterministic
        return _bounded((int(whole) + COCOA_EPOCH_OFFSET_S) * NS + frac_ns)
    return _bounded((int(v) + COCOA_EPOCH_OFFSET_S) * NS)


def ms_to_ns(value: Any) -> int | None:
    v = _num(value)
    if not v or v < 0:
        return None
    return _bounded(int(v) * 1_000_000)


def s_to_ns(value: Any) -> int | None:
    v = _num(value)
    if not v or v < 0:
        return None
    return _bounded(int(v) * NS)


def ios_message_date_to_ns(value: Any) -> int | None:
    """sms.db ``date``: nanoseconds since 2001 on iOS 11+, seconds since 2001 before."""
    v = _num(value)
    if not v:
        return None
    if abs(v) > 100_000_000_000:  # > ~3170 years in seconds: must be nanoseconds
        return _bounded(int(v) + COCOA_EPOCH_OFFSET_S * NS)
    return cocoa_to_ns(v)


def round6(value: Any) -> str | None:
    """Coordinates as fixed 6-decimal strings (no binary floats in canonical JSON)."""
    v = _num(value)
    if v is None:
        return None
    return f"{float(v):.6f}"


def text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)
