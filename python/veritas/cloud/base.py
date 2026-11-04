"""Shared plumbing for the cloud audit-log normalizers (also reused by ``veritas.mobile``).

Design rules (docs/ARCHITECTURE.md section 7):

* no wall-clock reads: every timestamp comes from the evidence;
* attrs are JSON-serializable scalars/lists/dicts with sorted keys, floats are rendered as
  strings so canonical JSON never carries binary floating point;
* malformed input raises :class:`ParserError` or is counted as a warning, never an uncaught
  exception.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import zlib
from dataclasses import dataclass, field
from datetime import date, datetime, time
from typing import Any, Iterable, Iterator

from veritas.timeline.schema import Desc, Event, iso_to_ns

PARSER_VERSION = "1.0.0"

GZIP_MAGIC = b"\x1f\x8b"
MAX_JSON_ATTR_CHARS = 4096
MAX_STRING_ATTR_CHARS = 8192
MAX_ATTR_DEPTH = 8
MAX_LIST_ITEMS = 256
MAX_WARNINGS = 1000

Source = "str | os.PathLike[str] | bytes | bytearray | memoryview"


try:  # share one exception hierarchy with veritas.parsers when that package is present
    from veritas.parsers.base import ParserError as _BaseParserError
except ImportError:  # pragma: no cover - standalone use without veritas.parsers
    _BaseParserError = Exception  # type: ignore[misc,assignment]


class ParserError(_BaseParserError):
    """Raised when evidence is structurally unusable by a parser.

    Partial damage (a bad line, a truncated record) is reported as a warning in the
    :class:`ParseResult`; a ParserError means the parser could not produce anything trustworthy.
    """


@dataclass(slots=True)
class ParseResult:
    events: list[Event] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    truncated_warnings: int = 0

    @property
    def warning_count(self) -> int:
        return len(self.warnings) + self.truncated_warnings

    def warn(self, text: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append(text)
        else:
            self.truncated_warnings += 1

    def extend(self, other: "ParseResult") -> None:
        self.events.extend(other.events)
        for w in other.warnings:
            self.warn(w)
        self.truncated_warnings += other.truncated_warnings

    def sorted(self) -> list[Event]:
        return sorted(self.events, key=Event.sort_key)

    def to_jsonl(self) -> str:
        return "".join(e.to_json() + "\n" for e in self.sorted())

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self) -> Iterator[Event]:
        """Iterating a result yields its Events in canonical order (pipeline ``parse`` contract)."""
        return iter(self.sorted())


def provenance_fields(provenance: Any, evidence_path: str = "", evidence_sha256: str = "") -> tuple[str, str]:
    """Resolve ``(evidence_path, evidence_sha256)`` from explicit kwargs or a Provenance-like object."""
    if provenance is not None:
        evidence_path = evidence_path or (getattr(provenance, "evidence_path", "") or "")
        evidence_sha256 = evidence_sha256 or (getattr(provenance, "evidence_sha256", "") or "")
    return evidence_path, evidence_sha256


def apply_provenance(result: ParseResult, provenance: Any) -> ParseResult:
    """Fill host/user from the provenance hints where the parser could not derive them."""
    if provenance is None:
        return result
    host = getattr(provenance, "host", None)
    user = getattr(provenance, "user", None)
    for ev in result.events:
        if ev.host is None and host:
            ev.host = str(host)
        if ev.user is None and user:
            ev.user = str(user)
    return result


# --------------------------------------------------------------------------- input handling


def is_path(source: Any) -> bool:
    return isinstance(source, (str, os.PathLike))


def source_name(source: Any) -> str:
    if is_path(source):
        return os.fspath(source).replace("\\", "/")
    return ""


def load_bytes(source: Any, *, max_bytes: int | None = None) -> bytes:
    """Return the raw bytes of ``source`` (path or bytes-like), transparently gunzipping."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    elif is_path(source):
        try:
            with open(source, "rb") as fh:
                data = fh.read() if max_bytes is None else fh.read(max_bytes)
        except OSError as exc:
            raise ParserError(f"cannot read {source_name(source)}: {exc}") from exc
    else:
        raise ParserError(f"unsupported source type {type(source).__name__}")
    if data[:2] == GZIP_MAGIC:
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError, zlib.error, ValueError) as exc:
            raise ParserError(f"corrupt gzip stream: {exc}") from exc
    return data


def decode_text(data: bytes) -> str:
    """Decode bytes as UTF-8 (BOM aware) replacing undecodable sequences."""
    if data[:3] == b"\xef\xbb\xbf":
        data = data[3:]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", errors="replace")


def iter_lines(text: str) -> Iterator[tuple[int, int, str]]:
    """Yield ``(line_number, char_offset, line)`` for non-empty lines."""
    pos = 0
    for n, raw in enumerate(text.splitlines(keepends=True), 1):
        line = raw.rstrip("\r\n")
        if line.strip():
            yield n, pos, line
        pos += len(raw)


_WS_RE = re.compile(r"[\s,]*")


def iter_json_values(text: str) -> Iterator[Any]:
    """Yield every top-level JSON value in ``text`` (single value, JSON Lines, concatenated).

    Raises :class:`ParserError` on the first undecodable region.
    """
    decoder = json.JSONDecoder()
    pos = 0
    length = len(text)
    while True:
        pos = _WS_RE.match(text, pos).end()
        if pos >= length:
            return
        try:
            value, pos = decoder.raw_decode(text, pos)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ParserError(f"invalid JSON at char {pos}: {exc}") from exc
        yield value


def iter_json_records(data: bytes, wrappers: Iterable[str] = ("Records", "records", "value", "items")) -> Iterator[dict]:
    """Yield dict records from a JSON document that may be an array, object-with-wrapper, or JSON Lines."""
    text = decode_text(data)
    if not text.strip():
        raise ParserError("empty JSON document")
    wrappers = tuple(wrappers)
    found = 0
    for value in iter_json_values(text):
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    found += 1
                    yield item
        elif isinstance(value, dict):
            unwrapped = False
            for key in wrappers:
                inner = value.get(key)
                if isinstance(inner, list):
                    unwrapped = True
                    for item in inner:
                        if isinstance(item, dict):
                            found += 1
                            yield item
                    break
            if not unwrapped:
                found += 1
                yield value
        else:
            raise ParserError(f"unexpected top-level JSON value of type {type(value).__name__}")
    if not found:
        raise ParserError("JSON document contains no records")


def split_log_fields(line: str) -> list[str]:
    """Split a space-delimited access-log line honouring ``"quoted"`` and ``[bracketed]`` fields."""
    fields: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c == " ":
            i += 1
            continue
        if c == '"':
            j = line.find('"', i + 1)
            if j < 0:
                fields.append(line[i + 1 :])
                break
            fields.append(line[i + 1 : j])
            i = j + 1
        elif c == "[":
            j = line.find("]", i + 1)
            if j < 0:
                fields.append(line[i + 1 :])
                break
            fields.append(line[i + 1 : j])
            i = j + 1
        else:
            j = line.find(" ", i)
            if j < 0:
                fields.append(line[i:])
                break
            fields.append(line[i:j])
            i = j
    return fields


# --------------------------------------------------------------------------- time helpers

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
_CLF_TIME_RE = re.compile(
    r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:\s*([+-]\d{4}|Z))?$"
)
_FRACTION_RE = re.compile(r"(\.\d{1,})")
_OFFSET_RE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


def normalize_iso(text: str) -> str:
    """Make common timestamp spellings acceptable to ``iso_to_ns`` (7-digit fractions, ``+0000``)."""
    t = text.strip()
    if " " in t and "T" not in t:
        t = t.replace(" ", "T", 1)
    m = _OFFSET_RE.search(t)
    tail = ""
    if m:
        tail = m.group(1)
        t = t[: m.start()]
        if tail != "Z" and ":" not in tail:
            tail = tail[:3] + ":" + tail[3:]
    frac = _FRACTION_RE.search(t)
    if frac and len(frac.group(1)) > 7:
        t = t[: frac.start()] + frac.group(1)[:7] + t[frac.end() :]
    return t + tail


def clf_to_iso(text: str) -> str | None:
    """``06/Feb/2019:00:00:38 +0000`` -> ``2019-02-06T00:00:38+00:00``."""
    m = _CLF_TIME_RE.match(text.strip())
    if not m:
        return None
    day, mon, year, hh, mm, ss, frac, off = m.groups()
    month = _MONTHS.get(mon.lower())
    if not month:
        return None
    iso = f"{int(year):04d}-{month:02d}-{int(day):02d}T{hh}:{mm}:{ss}"
    if frac:
        iso += "." + frac[:6]
    if off and off != "Z":
        iso += off[:3] + ":" + off[3:]
    else:
        iso += "+00:00"
    return iso


def parse_time(text: Any) -> int | None:
    """Parse an ISO-8601-ish string via :func:`iso_to_ns` after normalization."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        return iso_to_ns(normalize_iso(text))
    except (ValueError, OverflowError, OSError):
        return None


def tz_of(text: Any) -> str | None:
    """Return the explicit timezone expressed in a timestamp string, or None."""
    if not isinstance(text, str):
        return None
    t = text.strip()
    if t.endswith("Z"):
        return "UTC"
    m = re.search(r"([+-])(\d{2}):?(\d{2})$", t)
    if m and "T" in t:
        sign, hh, mm = m.groups()
        if hh == "00" and mm == "00":
            return "UTC"
        return f"{sign}{hh}:{mm}"
    return None


# --------------------------------------------------------------------------- attrs helpers


def jsonable(value: Any, depth: int = 0) -> Any:
    """Coerce an arbitrary decoded value into the attrs vocabulary (str/int/bool/None/list/dict)."""
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str) and len(value) > MAX_STRING_ATTR_CHARS:
            return value[:MAX_STRING_ATTR_CHARS] + "..."
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return str(value)
        if value.is_integer() and abs(value) < 2**53:
            return int(value)
        return repr(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        b = bytes(value)
        return b[:MAX_STRING_ATTR_CHARS // 2].hex()
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.strftime("%Y-%m-%dT%H:%M:%S") + f".{value.microsecond:06d}Z"
        return value.isoformat()
    if isinstance(value, (date, time)):
        return value.isoformat()
    if depth >= MAX_ATTR_DEPTH:
        return "..."
    if isinstance(value, dict):
        return {str(k): jsonable(v, depth + 1) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        if isinstance(value, (set, frozenset)):
            items = sorted(items, key=str)
        out = [jsonable(v, depth + 1) for v in items[:MAX_LIST_ITEMS]]
        if len(items) > MAX_LIST_ITEMS:
            out.append(f"... {len(items) - MAX_LIST_ITEMS} more")
        return out
    if hasattr(value, "data") and type(value).__name__ == "UID":
        return int(value.data)
    return str(value)


def bounded_json(value: Any, limit: int = MAX_JSON_ATTR_CHARS) -> tuple[Any, bool]:
    """Return ``(attr_value, truncated)``: the structure itself when small, else a cut JSON string."""
    if value is None:
        return None, False
    coerced = jsonable(value)
    text = json.dumps(coerced, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(text) <= limit:
        return coerced, False
    return text[:limit] + "...", True


def clean_attrs(attrs: dict[str, Any], *, drop_none: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in sorted(attrs):
        val = jsonable(attrs[key])
        if drop_none and val is None:
            continue
        out[key] = val
    return out


def first(d: Any, *keys: str, default: Any = None) -> Any:
    """Return the first present, non-empty key from a dict (case-sensitive)."""
    if not isinstance(d, dict):
        return default
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


def as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value == value else None
    if isinstance(value, str):
        v = value.strip()
        if v in ("", "-"):
            return None
        try:
            return int(v)
        except ValueError:
            try:
                return int(float(v))
            except ValueError:
                return None
    return None


def fixed6(value: Any) -> str | None:
    """Coordinates / fractional numbers as fixed 6-decimal strings (no floats in canonical JSON)."""
    if value is None or isinstance(value, bool):
        return None
    try:
        v = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if v != v or v in (float("inf"), float("-inf")):
        return None
    return f"{v:.6f}"


def dash_none(value: Any) -> Any:
    return None if value in ("-", "", None) else value


def redact_last4(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value)
    if len(s) <= 4:
        return "*" * len(s)
    return "*" * (len(s) - 4) + s[-4:]


# --------------------------------------------------------------------------- event factory


def make_event(
    *,
    data_type: str,
    timestamp_desc: str,
    message: str,
    timestamp: int | None,
    source_short: str,
    source_long: str,
    parser: str,
    evidence_path: str = "",
    evidence_sha256: str = "",
    offset: int = 0,
    host: str | None = None,
    user: str | None = None,
    timezone: str | None = None,
    attrs: dict[str, Any] | None = None,
) -> Event:
    if timestamp is None:
        timestamp_desc = Desc.NOT_A_TIME
    return Event(
        data_type=data_type,
        timestamp_desc=timestamp_desc,
        message=message,
        timestamp=timestamp,
        source_short=source_short,
        source_long=source_long,
        evidence_sha256=evidence_sha256,
        evidence_path=evidence_path,
        offset=int(offset),
        parser=parser,
        parser_version=PARSER_VERSION,
        host=str(host) if host not in (None, "") else None,
        user=str(user) if user not in (None, "") else None,
        timezone=timezone,
        skew_ns=0,
        attrs=clean_attrs(attrs or {}),
    )


class guard:
    """Context manager turning any unexpected exception into :class:`ParserError`.

    Expected damage is handled explicitly inside parsers; this is the last line of defence that
    keeps the "never an uncaught exception" promise for arbitrary bytes.
    """

    def __init__(self, what: str) -> None:
        self.what = what

    def __enter__(self) -> "guard":
        return self

    def __exit__(self, exc_type, exc, tb) -> Any:
        if exc is None or isinstance(exc, ParserError):
            return False
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            return False
        raise ParserError(f"{self.what}: {type(exc).__name__}: {exc}") from exc
