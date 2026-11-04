"""Parser protocol, provenance and the shared ``BaseParser`` scaffolding.

Every Python artifact parser lives under ``veritas.parsers`` and follows the same contract:

* ``name`` / ``version`` identify the parser in ``Event.parser`` / ``Event.parser_version``.
* ``matches(path, head_bytes)`` is a cheap sniff (file name plus the first bytes) used by the
  registry to pick parsers for a file.
* ``parse(path, provenance)`` yields :class:`veritas.timeline.schema.Event` objects.

Robustness rules (docs/THREAT_MODEL.md T3): malformed input never escapes as an arbitrary
exception. ``BaseParser.parse`` converts anything that is not already a :class:`ParserError`
into one, and record-level problems are counted into ``warnings`` while the parser keeps going.
Parsers never read the wall clock; every timestamp comes from the evidence (or from hints the
caller supplies through :class:`Provenance`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator, Protocol, runtime_checkable

from veritas.timeline.schema import Desc, Event

MAX_STRING = 64 * 1024  # bytes/characters kept for any single string attribute
MAX_WARNINGS = 1000  # warnings retained verbatim; the counter keeps counting past this


class ParserError(Exception):
    """Raised for unrecoverable problems (wrong format, truncated header, unreadable file)."""


@dataclass(slots=True)
class Provenance:
    """Where the evidence came from plus optional hints the parser may use.

    ``year_hint``  Year used for syslog-style timestamps that carry no year. When absent the
                   parser falls back to ``mtime_ns`` (year of the file modification time) and,
                   failing that, to 1970 with a warning. Nothing is ever read from the clock.
    ``mtime_ns``   Modification time of the evidence file (ns since epoch) as recorded by the
                   acquisition, used for ``Not a time`` inventory-style artifacts (cron, systemd
                   units, ssh config) that have no timestamp of their own.
    ``host`` / ``user``  Optional attributions applied to every event when the parser cannot
                   derive them itself.
    """

    evidence_sha256: str = ""
    evidence_path: str = ""
    year_hint: int | None = None
    mtime_ns: int | None = None
    host: str | None = None
    user: str | None = None
    timezone: str | None = None


@runtime_checkable
class Parser(Protocol):
    name: str
    version: str

    def matches(self, path: str, head_bytes: bytes) -> bool: ...

    def parse(self, path: str, provenance: Provenance) -> Iterator[Event]: ...


def clip(value: Any, limit: int = MAX_STRING) -> Any:
    """Cap strings/bytes at ``limit``; bytes are decoded leniently so attrs stay JSON-safe."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value[:limit].decode("utf-8", "replace")
    if isinstance(value, str) and len(value) > limit:
        return value[:limit]
    return value


def json_safe(value: Any, depth: int = 0) -> Any:
    """Coerce a value into the JSON subset allowed in ``Event.attrs``.

    Floats are rounded to 6 decimals (ARCHITECTURE.md section 7 forbids them where avoidable,
    callers should convert to integers first); bytes become text; unknown objects become ``str``.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return clip(value) if isinstance(value, str) else value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return round(value, 6)
    if isinstance(value, bytes):
        return clip(value)
    if depth > 8:
        return clip(str(value))
    if isinstance(value, dict):
        return {str(k): json_safe(v, depth + 1) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        if isinstance(value, (set, frozenset)):
            items = sorted(items, key=str)
        return [json_safe(v, depth + 1) for v in items[:10000]]
    return clip(str(value))


class BaseParser:
    """Shared scaffolding; subclasses implement ``_parse`` and ``matches``."""

    name: str = "base"
    version: str = "1.0"
    source_short: str = "LOG"
    source_long: str = ""
    #: Lower-case file-name fragments that make ``matches`` succeed when no magic applies.
    filename_hints: tuple[str, ...] = ()

    def __init__(self) -> None:
        self.warnings: list[str] = []
        self.warning_count: int = 0
        self._prov: Provenance = Provenance()

    # ------------------------------------------------------------------ protocol
    def matches(self, path: str, head_bytes: bytes) -> bool:
        lower = path.replace("\\", "/").lower()
        base = lower.rsplit("/", 1)[-1]
        return any(h in base for h in self.filename_hints)

    def parse(self, path: str, provenance: Provenance | None = None) -> Iterator[Event]:
        self.warnings = []
        self.warning_count = 0
        self._prov = provenance or Provenance()
        try:
            yield from self._parse(path, self._prov)
        except ParserError:
            raise
        except Exception as exc:  # noqa: BLE001 - the whole point is to never leak
            raise ParserError(f"{self.name}: {type(exc).__name__}: {exc}") from exc

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:  # pragma: no cover - abstract
        raise NotImplementedError

    # ------------------------------------------------------------------ helpers
    def warn(self, message: str) -> None:
        self.warning_count += 1
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append(clip(message, 512))

    def event(
        self,
        data_type: str,
        timestamp_desc: str,
        message: str,
        timestamp: int | None = None,
        *,
        offset: int = 0,
        attrs: dict[str, Any] | None = None,
        host: str | None = None,
        user: str | None = None,
        timezone: str | None = None,
        source_short: str | None = None,
        source_long: str | None = None,
    ) -> Event:
        prov = self._prov
        if timestamp is None:
            timestamp_desc = Desc.NOT_A_TIME
        return Event(
            data_type=data_type,
            timestamp_desc=timestamp_desc,
            message=clip(message, 4096) or "",
            timestamp=int(timestamp) if timestamp is not None else None,
            source_short=source_short if source_short is not None else self.source_short,
            source_long=source_long if source_long is not None else (self.source_long or self.name),
            evidence_sha256=prov.evidence_sha256,
            evidence_path=prov.evidence_path,
            offset=int(offset),
            parser=self.name,
            parser_version=self.version,
            host=host if host is not None else prov.host,
            user=user if user is not None else prov.user,
            timezone=timezone if timezone is not None else prov.timezone,
            attrs=json_safe(attrs or {}),
        )


def read_head(path: str, size: int = 4096) -> bytes:
    """Return the first ``size`` bytes of a file (empty on error)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


COCOA_EPOCH_S = 978_307_200


def cocoa_to_ns(value: Any) -> int | None:
    """Cocoa/Core Data time (seconds since 2001-01-01 UTC, float) -> ns, rounded to the microsecond.

    Rounding to microseconds avoids float noise in the low digits so output is deterministic and
    comparable with plaso (which stores microseconds). ``None``/0/NaN -> ``None``.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v != v or v == 0 or abs(v) > 1e11:
        return None
    return (int(round(v * 1_000_000)) + COCOA_EPOCH_S * 1_000_000) * 1000


def cocoa_ns_or_s_to_ns(value: Any) -> int | None:
    """Apple 'date' columns that are seconds (older) or nanoseconds (High Sierra+) since 2001."""
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > 10**11:
        return value + COCOA_EPOCH_S * 1_000_000_000
    return cocoa_to_ns(value)
