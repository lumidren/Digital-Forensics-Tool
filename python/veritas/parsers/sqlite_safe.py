"""Read-only, side-effect free SQLite access for evidence databases.

Evidence must never be modified. Two mechanisms guarantee that here:

1. Databases are opened through a ``file:`` URI with ``mode=ro&immutable=1``. ``immutable``
   tells SQLite the file cannot change under it, so it takes no locks and never creates the
   ``-shm``/``-journal`` side files next to the evidence.
2. When a ``-wal`` or ``-journal`` companion exists next to the database the live content is
   partly inside that file, and ``immutable=1`` would ignore it. In that case the database and
   its companions are copied into a private temporary directory and opened there with
   ``mode=ro`` (no ``immutable``) so SQLite can replay the WAL / roll back the journal in the
   copy. The copy is removed when the context manager exits.

Everything is exposed as a context manager (:func:`open_sqlite`) plus small introspection
helpers (:func:`tables`, :func:`columns`, :func:`has_table`). Row access streams through the
cursor; callers must not ``fetchall`` large tables.
"""
from __future__ import annotations

import contextlib
import os
import pathlib
import shutil
import sqlite3
import tempfile
from typing import Any, Iterator

from veritas.parsers.base import ParserError, clip

SQLITE_MAGIC = b"SQLite format 3\x00"
COMPANIONS = ("-wal", "-journal", "-shm")


def is_sqlite(head: bytes) -> bool:
    return head[:16] == SQLITE_MAGIC


def _uri(path: pathlib.Path, immutable: bool) -> str:
    uri = path.resolve().as_uri()
    uri += "?mode=ro"
    if immutable:
        uri += "&immutable=1"
    return uri


@contextlib.contextmanager
def open_sqlite(path: str | os.PathLike[str]) -> Iterator[sqlite3.Connection]:
    """Open ``path`` read-only. See the module docstring for the WAL/journal handling."""
    src = pathlib.Path(path)
    if not src.is_file():
        raise ParserError(f"sqlite: not a file: {src}")
    companions = [src.with_name(src.name + ext) for ext in COMPANIONS]
    needs_copy = any(c.is_file() and c.stat().st_size > 0 for c in companions[:2])
    tmpdir: tempfile.TemporaryDirectory[str] | None = None
    conn: sqlite3.Connection | None = None
    try:
        if needs_copy:
            tmpdir = tempfile.TemporaryDirectory(prefix="veritas-sqlite-")
            target = pathlib.Path(tmpdir.name) / src.name
            shutil.copyfile(src, target)
            for c in companions:
                if c.is_file():
                    shutil.copyfile(c, target.with_name(target.name + c.name[len(src.name):]))
            conn = sqlite3.connect(_uri(target, immutable=False), uri=True)
        else:
            conn = sqlite3.connect(_uri(src, immutable=True), uri=True)
        conn.row_factory = sqlite3.Row
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
        try:
            # Forces the header to be validated now rather than on the first real query.
            conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
        except sqlite3.DatabaseError as exc:
            raise ParserError(f"sqlite: {src.name}: {exc}") from exc
        yield conn
    finally:
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()
        if tmpdir is not None:
            with contextlib.suppress(Exception):
                tmpdir.cleanup()


def tables(conn: sqlite3.Connection) -> list[str]:
    try:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
    except sqlite3.DatabaseError as exc:
        raise ParserError(f"sqlite: schema unreadable: {exc}") from exc
    return [r[0] for r in rows]


def has_table(conn: sqlite3.Connection, name: str) -> bool:
    return name in tables(conn)


def columns(conn: sqlite3.Connection, table: str) -> list[str]:
    if not table.replace("_", "").isalnum():
        raise ParserError(f"sqlite: refusing table name {table!r}")
    try:
        return [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")').fetchall()]  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query - sqlite3 PRAGMA on a quoted identifier validated against sqlite_master
    except sqlite3.DatabaseError as exc:
        raise ParserError(f"sqlite: table_info({table}) failed: {exc}") from exc


def rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> Iterator[sqlite3.Row]:
    """Stream rows; converts SQLite failures into ``ParserError``."""
    try:
        cur = conn.execute(sql, params)
        while True:
            chunk = cur.fetchmany(512)
            if not chunk:
                return
            yield from chunk
    except sqlite3.DatabaseError as exc:
        raise ParserError(f"sqlite: query failed: {exc}") from exc


def row_dict(row: sqlite3.Row) -> dict[str, Any]:
    """``sqlite3.Row`` -> plain dict with strings clipped and blobs decoded leniently."""
    out: dict[str, Any] = {}
    for key in row.keys():
        val = row[key]
        if isinstance(val, (bytes, memoryview)):
            val = clip(bytes(val))
        elif isinstance(val, str):
            val = clip(val)
        out[key] = val
    return out


def col(row: sqlite3.Row, name: str, default: Any = None) -> Any:
    """Column access that tolerates schema variants (missing column -> default)."""
    try:
        val = row[name]
    except (IndexError, KeyError):
        return default
    if isinstance(val, (bytes, memoryview)):
        return clip(bytes(val))
    if isinstance(val, str):
        return clip(val)
    return val


def to_int(value: Any, default: int | None = None) -> int | None:
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default
