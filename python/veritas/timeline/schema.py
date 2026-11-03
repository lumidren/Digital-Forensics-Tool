"""Unified timeline event schema (Python mirror of ``crates/veritas-timeline``).

Every parser, Rust or Python, emits this shape. Field semantics are documented in
docs/ARCHITECTURE.md section 6. Timestamps are integer nanoseconds since the Unix epoch, UTC.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

NS = 1_000_000_000
FILETIME_EPOCH_DIFF_100NS = 116_444_736_000_000_000
WEBKIT_EPOCH_DIFF_US = 11_644_473_600_000_000
COCOA_EPOCH_OFFSET_S = 978_307_200


class Desc:
    CREATION = "Creation Time"
    MODIFICATION = "Content Modification Time"
    METADATA_MODIFICATION = "Metadata Modification Time"
    ACCESS = "Last Access Time"
    LAST_RUN = "Last Time Executed"
    PREVIOUS_RUN = "Previous Last Time Executed"
    LAST_VISITED = "Last Visited Time"
    LAST_LOGIN = "Last Login Time"
    EVENT = "Event Time"
    INSTALLATION = "Installation Time"
    EXPIRATION = "Expiration Time"
    START = "Start Time"
    END = "End Time"
    SENT = "Sent Time"
    RECEIVED = "Received Time"
    NOT_A_TIME = "Not a time"


@dataclass(slots=True)
class Event:
    data_type: str
    timestamp_desc: str
    message: str
    timestamp: int | None = None
    source_short: str = ""
    source_long: str = ""
    evidence_sha256: str = ""
    evidence_path: str = ""
    offset: int = 0
    parser: str = ""
    parser_version: str = ""
    host: str | None = None
    user: str | None = None
    timezone: str | None = None
    skew_ns: int = 0
    attrs: dict[str, Any] = field(default_factory=dict)

    def sort_key(self) -> tuple:
        return (
            self.timestamp if self.timestamp is not None else -(2**63),
            self.data_type,
            self.evidence_path,
            self.offset,
            self.timestamp_desc,
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Deterministic attrs ordering and drop empty optionals the Rust side skips.
        d["attrs"] = {k: d["attrs"][k] for k in sorted(d["attrs"])}
        for k in ("host", "user", "timezone"):
            if d[k] is None:
                del d[k]
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=False)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        return cls(
            data_type=d["data_type"],
            timestamp_desc=d["timestamp_desc"],
            message=d["message"],
            timestamp=d.get("timestamp"),
            source_short=d.get("source_short", ""),
            source_long=d.get("source_long", ""),
            evidence_sha256=d.get("evidence_sha256", ""),
            evidence_path=d.get("evidence_path", ""),
            offset=int(d.get("offset", 0)),
            parser=d.get("parser", ""),
            parser_version=d.get("parser_version", ""),
            host=d.get("host"),
            user=d.get("user"),
            timezone=d.get("timezone"),
            skew_ns=int(d.get("skew_ns", 0)),
            attrs=dict(d.get("attrs", {})),
        )

    def datetime(self) -> datetime | None:
        if self.timestamp is None:
            return None
        return datetime.fromtimestamp(self.timestamp // NS, tz=timezone.utc).replace(
            microsecond=(self.timestamp % NS) // 1000
        )


def filetime_to_ns(ft: int) -> int | None:
    if not ft:
        return None
    rel = ft - FILETIME_EPOCH_DIFF_100NS
    return rel * 100


def unix_to_ns(secs: float | int, nanos: int = 0) -> int | None:
    if secs is None:
        return None
    return int(secs) * NS + int(nanos) + (int(round((secs - int(secs)) * NS)) if isinstance(secs, float) else 0)


def webkit_us_to_ns(us: int) -> int | None:
    if not us:
        return None
    return (us - WEBKIT_EPOCH_DIFF_US) * 1000


def cocoa_secs_to_ns(secs: float) -> int | None:
    if secs is None:
        return None
    return int(round((secs + COCOA_EPOCH_OFFSET_S) * NS))


def iso_to_ns(text: str) -> int | None:
    """Parse ISO-8601 / RFC 3339 text (with or without fractional seconds, Z or offset)."""
    if not text:
        return None
    t = text.strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp()) * NS + dt.microsecond * 1000


def format_ns(ns: int) -> str:
    dt = datetime.fromtimestamp(ns // NS, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{(ns % NS) // 1000:06d}Z"


def sorted_events(events: Iterable[Event]) -> list[Event]:
    return sorted(events, key=Event.sort_key)


def write_jsonl(events: Iterable[Event], fh) -> int:
    n = 0
    for e in sorted_events(events):
        fh.write(e.to_json())
        fh.write("\n")
        n += 1
    return n


def read_jsonl(fh) -> Iterator[Event]:
    for line in fh:
        line = line.strip()
        if line:
            yield Event.from_dict(json.loads(line))
