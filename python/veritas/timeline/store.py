"""Timeline storage backends.

Two backends share one interface:

* :class:`SqliteTimelineStore` — the native profile. One SQLite file per deployment with an
  ``events`` table, an FTS5 index over message and attribute text, and covering indexes on
  ``(case_id, timestamp)`` and ``(case_id, data_type)``. Tens of millions of rows search in well
  under a second on an SSD for bounded time ranges; see docs/BENCHMARKS.md for measurements.
* :class:`ClickHouseTimelineStore` — the cluster profile, over the HTTP interface.

Every query is scoped by ``case_id`` inside this module, never by the caller.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Protocol

from .schema import Event

SCHEMA_VERSION = 1


@dataclass(slots=True)
class Query:
    text: str | None = None
    start_ns: int | None = None
    end_ns: int | None = None
    data_types: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    parsers: list[str] = field(default_factory=list)
    attr_equals: dict[str, str] = field(default_factory=dict)
    include_untimed: bool = False
    limit: int = 200
    offset: int = 0
    descending: bool = False


@dataclass(slots=True)
class StoredEvent:
    id: int
    event: Event


@dataclass(slots=True)
class SearchResult:
    total: int
    events: list[StoredEvent]


@dataclass(slots=True)
class Bucket:
    start_ns: int
    count: int


class TimelineStore(Protocol):
    def ingest(self, case_id: str, events: Iterable[Event]) -> int: ...
    def search(self, case_id: str, query: Query) -> SearchResult: ...
    def histogram(self, case_id: str, query: Query, bucket_ns: int) -> list[Bucket]: ...
    def facets(self, case_id: str, query: Query, column: str, limit: int = 50) -> list[tuple[str, int]]: ...
    def count(self, case_id: str) -> int: ...
    def get(self, case_id: str, event_id: int) -> StoredEvent | None: ...
    def iter_events(self, case_id: str, query: Query | None = None) -> Iterator[StoredEvent]: ...
    def delete_case(self, case_id: str) -> int: ...


def event_fingerprint(case_id: str, e: Event) -> str:
    """Stable identity of an event, so re-running a parser never duplicates rows."""
    payload = json.dumps(
        [case_id, e.timestamp, e.timestamp_desc, e.data_type, e.evidence_sha256, e.evidence_path, e.offset, e.parser, e.message],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _attrs_text(attrs: dict[str, Any]) -> str:
    parts: list[str] = []
    for k in sorted(attrs):
        v = attrs[k]
        if isinstance(v, (dict, list)):
            v = json.dumps(v, ensure_ascii=False, sort_keys=True)
        parts.append(f"{k}={v}")
    return " ".join(parts)


_FACET_COLUMNS = {"data_type", "host", "user", "parser", "evidence_sha256", "timestamp_desc", "source_short"}


class SqliteTimelineStore:
    """SQLite + FTS5 backend."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._local = threading.local()
        with self._conn() as c:
            self._init_schema(c)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA cache_size=-262144")
            self._local.conn = conn
        return conn

    @staticmethod
    def _init_schema(c: sqlite3.Connection) -> None:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY,
                case_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                timestamp INTEGER,
                timestamp_desc TEXT NOT NULL,
                data_type TEXT NOT NULL,
                message TEXT NOT NULL,
                source_short TEXT NOT NULL,
                source_long TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,
                evidence_path TEXT NOT NULL,
                offset INTEGER NOT NULL,
                parser TEXT NOT NULL,
                parser_version TEXT NOT NULL,
                host TEXT,
                user TEXT,
                timezone TEXT,
                skew_ns INTEGER NOT NULL DEFAULT 0,
                attrs TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_events_case_ts ON events(case_id, timestamp);
            CREATE INDEX IF NOT EXISTS ix_events_case_type ON events(case_id, data_type, timestamp);
            CREATE INDEX IF NOT EXISTS ix_events_case_evidence ON events(case_id, evidence_sha256);
            CREATE INDEX IF NOT EXISTS ix_events_case_host ON events(case_id, host);
            CREATE INDEX IF NOT EXISTS ix_events_case_user ON events(case_id, user);
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                message, attrs_text, evidence_path, content='', tokenize='unicode61 remove_diacritics 2'
            );
            """
        )
        c.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))

    def ingest(self, case_id: str, events: Iterable[Event]) -> int:
        c = self._conn()
        inserted = 0
        c.execute("BEGIN")
        try:
            batch: list[tuple] = []
            for e in events:
                fp = event_fingerprint(case_id, e)
                batch.append(
                    (
                        case_id, fp, e.timestamp, e.timestamp_desc, e.data_type, e.message, e.source_short, e.source_long,
                        e.evidence_sha256, e.evidence_path, e.offset, e.parser, e.parser_version, e.host, e.user,
                        e.timezone, e.skew_ns, json.dumps(e.attrs, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    )
                )
                if len(batch) >= 5000:
                    inserted += self._insert_batch(c, batch)
                    batch = []
            if batch:
                inserted += self._insert_batch(c, batch)
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
        return inserted

    def _insert_batch(self, c: sqlite3.Connection, batch: list[tuple]) -> int:
        n = 0
        for row in batch:
            cur = c.execute(
                """INSERT OR IGNORE INTO events(case_id, fingerprint, timestamp, timestamp_desc, data_type, message,
                   source_short, source_long, evidence_sha256, evidence_path, offset, parser, parser_version, host, user,
                   timezone, skew_ns, attrs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                row,
            )
            if cur.rowcount == 1:
                rowid = cur.lastrowid
                attrs = json.loads(row[17])
                c.execute(
                    "INSERT INTO events_fts(rowid, message, attrs_text, evidence_path) VALUES(?,?,?,?)",
                    (rowid, row[5], _attrs_text(attrs), row[9]),
                )
                n += 1
        return n

    # --- query building -------------------------------------------------------------------
    def _where(self, case_id: str, q: Query) -> tuple[str, list[Any]]:
        # THREAT:T4.2 every statement is scoped to one case here, independent of the caller.
        clauses = ["e.case_id = ?"]
        params: list[Any] = [case_id]
        if q.start_ns is not None:
            clauses.append("e.timestamp >= ?")
            params.append(q.start_ns)
        if q.end_ns is not None:
            clauses.append("e.timestamp < ?")
            params.append(q.end_ns)
        if not q.include_untimed:
            clauses.append("e.timestamp IS NOT NULL")
        for col, values in (("data_type", q.data_types), ("host", q.hosts), ("user", q.users),
                            ("evidence_sha256", q.evidence), ("parser", q.parsers)):
            if values:
                clauses.append(f"e.{col} IN ({','.join('?' * len(values))})")
                params.extend(values)
        for k, v in sorted(q.attr_equals.items()):
            clauses.append("CAST(json_extract(e.attrs, ?) AS TEXT) = ?")
            params.extend([f"$.{k}", v])
        if q.text:
            clauses.append("e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
            params.append(_fts_query(q.text))
        return " AND ".join(clauses), params

    def search(self, case_id: str, query: Query) -> SearchResult:
        c = self._conn()
        where, params = self._where(case_id, query)
        total = c.execute(f"SELECT COUNT(*) FROM events e WHERE {where}", params).fetchone()[0]  # nosec B608 - identifiers are fixed column names; values are bound parameters or escaped
        order = "DESC" if query.descending else "ASC"
        rows = c.execute(
            f"SELECT * FROM events e WHERE {where} ORDER BY e.timestamp {order}, e.data_type, e.evidence_path, e.offset, e.id LIMIT ? OFFSET ?",  # nosec B608 - identifiers are fixed column names; values are bound parameters or escaped
            params + [max(0, min(query.limit, 10_000)), max(0, query.offset)],
        ).fetchall()
        return SearchResult(total=total, events=[self._row_to_stored(r, c) for r in rows])

    def histogram(self, case_id: str, query: Query, bucket_ns: int) -> list[Bucket]:
        if bucket_ns <= 0:
            raise ValueError("bucket_ns must be positive")
        c = self._conn()
        q = dataclasses.replace(query, include_untimed=False)
        where, params = self._where(case_id, q)
        rows = c.execute(
            f"SELECT (e.timestamp / ?) * ? AS b, COUNT(*) FROM events e WHERE {where} GROUP BY b ORDER BY b",  # nosec B608 - identifiers are fixed column names; values are bound parameters or escaped
            [bucket_ns, bucket_ns] + params,
        ).fetchall()
        return [Bucket(start_ns=int(r[0]), count=int(r[1])) for r in rows]

    def facets(self, case_id: str, query: Query, column: str, limit: int = 50) -> list[tuple[str, int]]:
        if column not in _FACET_COLUMNS:
            raise ValueError(f"facet column not allowed: {column}")
        c = self._conn()
        where, params = self._where(case_id, query)
        rows = c.execute(
            f"SELECT e.{column}, COUNT(*) AS n FROM events e WHERE {where} GROUP BY e.{column} ORDER BY n DESC, e.{column} LIMIT ?",  # nosec B608 - identifiers are fixed column names; values are bound parameters or escaped
            params + [limit],
        ).fetchall()
        return [(r[0] if r[0] is not None else "", int(r[1])) for r in rows]

    def count(self, case_id: str) -> int:
        return int(self._conn().execute("SELECT COUNT(*) FROM events WHERE case_id = ?", (case_id,)).fetchone()[0])

    def get(self, case_id: str, event_id: int) -> StoredEvent | None:
        c = self._conn()
        row = c.execute("SELECT * FROM events e WHERE e.case_id = ? AND e.id = ?", (case_id, event_id)).fetchone()
        return self._row_to_stored(row, c) if row else None

    def iter_events(self, case_id: str, query: Query | None = None) -> Iterator[StoredEvent]:
        c = self._conn()
        q = query or Query(include_untimed=True, limit=10**9)
        where, params = self._where(case_id, q)
        cur = c.execute(f"SELECT * FROM events e WHERE {where} ORDER BY e.timestamp, e.data_type, e.evidence_path, e.offset, e.id", params)  # nosec B608 - identifiers are fixed column names; values are bound parameters or escaped
        for row in cur:
            yield self._row_to_stored(row, c)

    def delete_case(self, case_id: str) -> int:
        c = self._conn()
        ids = [r[0] for r in c.execute("SELECT id FROM events WHERE case_id = ?", (case_id,))]
        c.execute("BEGIN")
        for i in ids:
            c.execute("INSERT INTO events_fts(events_fts, rowid, message, attrs_text, evidence_path) VALUES('delete', ?, '', '', '')", (i,))
        c.execute("DELETE FROM events WHERE case_id = ?", (case_id,))
        c.execute("COMMIT")
        return len(ids)

    @staticmethod
    def _row_to_stored(row: tuple, c: sqlite3.Connection) -> StoredEvent:
        cols = [d[0] for d in c.execute("SELECT * FROM events LIMIT 0").description]
        d = dict(zip(cols, row))
        ev = Event(
            data_type=d["data_type"], timestamp_desc=d["timestamp_desc"], message=d["message"], timestamp=d["timestamp"],
            source_short=d["source_short"], source_long=d["source_long"], evidence_sha256=d["evidence_sha256"],
            evidence_path=d["evidence_path"], offset=d["offset"], parser=d["parser"], parser_version=d["parser_version"],
            host=d["host"], user=d["user"], timezone=d["timezone"], skew_ns=d["skew_ns"], attrs=json.loads(d["attrs"]),
        )
        return StoredEvent(id=int(d["id"]), event=ev)


def _fts_query(text: str) -> str:
    """Turn free text into a safe FTS5 query: each token quoted, implicit AND, prefix for trailing *."""
    tokens = []
    for raw in text.split():
        prefix = raw.endswith("*")
        tok = raw.rstrip("*").replace('"', '""')
        if not tok:
            continue
        tokens.append(f'"{tok}"' + ("*" if prefix else ""))
    return " AND ".join(tokens) if tokens else '""'


def _ch_str(s: str) -> str:
    """ClickHouse string literal with backslash and quote escaping."""
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


class ClickHouseTimelineStore:
    """ClickHouse backend over HTTP. Used in the cluster profile.

    Table layout: MergeTree ordered by (case_id, timestamp, data_type) with a tokenbf_v1 skip
    index on message for text search, and a materialized ``attrs`` String column (JSON).
    Only exercised by tests when ``CLICKHOUSE_URL`` is set.
    """

    def __init__(self, url: str, database: str = "veritas", user: str | None = None, password: str | None = None):
        import httpx  # local import so the native profile never needs it at import time

        self._url = url.rstrip("/")
        self._db = database
        self._client = httpx.Client(timeout=60.0, auth=(user, password) if user else None)
        self._sql(f"CREATE DATABASE IF NOT EXISTS {database}")
        self._sql(
            f"""
            CREATE TABLE IF NOT EXISTS {database}.events (
                case_id String, fingerprint String, timestamp Nullable(Int64), timestamp_desc String, data_type String,
                message String, source_short String, source_long String, evidence_sha256 String, evidence_path String,
                offset Int64, parser String, parser_version String, host Nullable(String), user Nullable(String),
                timezone Nullable(String), skew_ns Int64, attrs String,
                INDEX ix_msg message TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
            ) ENGINE = ReplacingMergeTree ORDER BY (case_id, fingerprint)
            """
        )

    def _sql(self, sql: str, body: bytes | None = None, params: dict[str, Any] | None = None) -> str:
        r = self._client.post(self._url, params={"query": sql, **(params or {})}, content=body)
        r.raise_for_status()
        return r.text

    def ingest(self, case_id: str, events: Iterable[Event]) -> int:
        lines = []
        for e in events:
            d = e.to_dict()
            d["case_id"] = case_id
            d["fingerprint"] = event_fingerprint(case_id, e)
            d["attrs"] = json.dumps(d["attrs"], ensure_ascii=False, sort_keys=True)
            lines.append(json.dumps(d, ensure_ascii=False))
        if not lines:
            return 0
        self._sql(f"INSERT INTO {self._db}.events FORMAT JSONEachRow", body=("\n".join(lines)).encode("utf-8"))
        return len(lines)

    def _where(self, case_id: str, q: Query) -> str:
        esc = _ch_str

        clauses = [f"case_id = {esc(case_id)}"]  # THREAT:T4.2
        if q.start_ns is not None:
            clauses.append(f"timestamp >= {int(q.start_ns)}")
        if q.end_ns is not None:
            clauses.append(f"timestamp < {int(q.end_ns)}")
        if not q.include_untimed:
            clauses.append("timestamp IS NOT NULL")
        for col, values in (("data_type", q.data_types), ("host", q.hosts), ("user", q.users),
                            ("evidence_sha256", q.evidence), ("parser", q.parsers)):
            if values:
                clauses.append(f"{col} IN ({','.join(esc(v) for v in values)})")
        for k, v in sorted(q.attr_equals.items()):
            clauses.append(f"(JSONExtractString(attrs, {esc(k)}) = {esc(v)} OR JSONExtractRaw(attrs, {esc(k)}) = {esc(v)})")
        if q.text:
            for tok in q.text.split():
                clauses.append(f"(positionCaseInsensitive(message, {esc(tok.rstrip('*'))}) > 0 OR positionCaseInsensitive(attrs, {esc(tok.rstrip('*'))}) > 0)")
        return " AND ".join(clauses)

    def search(self, case_id: str, query: Query) -> SearchResult:
        where = self._where(case_id, query)
        total = int(self._sql(f"SELECT count() FROM {self._db}.events FINAL WHERE {where}").strip() or 0)  # nosec B608 - identifiers are fixed column names; values are bound parameters or escaped
        order = "DESC" if query.descending else "ASC"
        text = self._sql(
            f"SELECT * FROM {self._db}.events FINAL WHERE {where} ORDER BY timestamp {order}, data_type, evidence_path, offset "  # nosec B608 - identifiers are fixed column names; values are bound parameters or escaped
            f"LIMIT {int(query.limit)} OFFSET {int(query.offset)} FORMAT JSONEachRow"
        )
        events = []
        for i, line in enumerate(text.splitlines()):
            d = json.loads(line)
            d["attrs"] = json.loads(d["attrs"])
            events.append(StoredEvent(id=i + query.offset, event=Event.from_dict(d)))
        return SearchResult(total=total, events=events)

    def histogram(self, case_id: str, query: Query, bucket_ns: int) -> list[Bucket]:
        where = self._where(case_id, dataclasses.replace(query, include_untimed=False))
        text = self._sql(
            f"SELECT intDiv(timestamp, {int(bucket_ns)}) * {int(bucket_ns)} AS b, count() AS n FROM {self._db}.events FINAL WHERE {where} GROUP BY b ORDER BY b FORMAT JSONEachRow"  # nosec B608 - identifiers are fixed column names; values are bound parameters or escaped
        )
        return [Bucket(start_ns=int(json.loads(l)["b"]), count=int(json.loads(l)["n"])) for l in text.splitlines()]

    def facets(self, case_id: str, query: Query, column: str, limit: int = 50) -> list[tuple[str, int]]:
        if column not in _FACET_COLUMNS:
            raise ValueError(f"facet column not allowed: {column}")
        where = self._where(case_id, query)
        text = self._sql(
            f"SELECT {column} AS v, count() AS n FROM {self._db}.events FINAL WHERE {where} GROUP BY v ORDER BY n DESC, v LIMIT {int(limit)} FORMAT JSONEachRow"  # nosec B608 - identifiers are fixed column names; values are bound parameters or escaped
        )
        return [((json.loads(l)["v"] or ""), int(json.loads(l)["n"])) for l in text.splitlines()]

    def count(self, case_id: str) -> int:
        return int(self._sql(f"SELECT count() FROM {self._db}.events FINAL WHERE case_id = {_ch_str(case_id)}").strip() or 0)  # nosec B608 - case id escaped

    def get(self, case_id: str, event_id: int) -> StoredEvent | None:
        res = self.search(case_id, Query(include_untimed=True, limit=1, offset=event_id))
        return res.events[0] if res.events else None

    def iter_events(self, case_id: str, query: Query | None = None) -> Iterator[StoredEvent]:
        q = query or Query(include_untimed=True)
        offset = 0
        while True:
            page = self.search(case_id, dataclasses.replace(q, limit=10_000, offset=offset))
            if not page.events:
                return
            yield from page.events
            offset += len(page.events)

    def delete_case(self, case_id: str) -> int:
        n = self.count(case_id)
        self._sql(f"ALTER TABLE {self._db}.events DELETE WHERE case_id = {_ch_str(case_id)}")  # nosec B608 - case id escaped
        return n


def open_store(url: str) -> TimelineStore:
    """``sqlite:///path/to/file.db`` or ``clickhouse://host:8123/db``."""
    if url.startswith("sqlite:///"):
        return SqliteTimelineStore(url[len("sqlite:///"):])
    if url.startswith("clickhouse://"):
        rest = url[len("clickhouse://"):]
        host, _, db = rest.partition("/")
        return ClickHouseTimelineStore(f"http://{host}", database=db or "veritas")
    raise ValueError(f"unsupported timeline store url: {url}")
