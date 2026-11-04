"""Base for line-oriented log parsers.

* Transparent decompression of gzip / bzip2 / xz input (by magic, not extension).
* Encoding detection: BOM (UTF-8, UTF-16 LE/BE), NUL-pattern heuristic for BOM-less UTF-16,
  strict UTF-8 probe on the first 64 KiB, otherwise Latin-1 (which never fails).
* Lines are streamed, never loaded wholesale, and each line is capped at 64 KiB; the rest of an
  over-long line is discarded with a warning.
* ``offset`` of an emitted event is the 1-based line number (byte offsets are meaningless after
  decompression / decoding).

Subclasses implement :meth:`TextLogParser.parse_line`; exceptions from a single line are turned
into warnings so one bad record never aborts a file.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
from typing import BinaryIO, Iterator

from veritas.parsers.base import MAX_STRING, BaseParser, ParserError, Provenance
from veritas.timeline.schema import Event

GZIP_MAGIC = b"\x1f\x8b"
BZ2_MAGIC = b"BZh"
XZ_MAGIC = b"\xfd7zXZ\x00"
MAX_LINE = MAX_STRING
PROBE = 64 * 1024


def open_binary(path: str) -> BinaryIO:
    """Open ``path`` for reading, decompressing gzip/bz2/xz transparently (by magic)."""
    fh: BinaryIO = open(path, "rb")  # noqa: SIM115 - caller closes
    head = fh.read(8)
    fh.seek(0)
    if head.startswith(GZIP_MAGIC):
        fh.close()
        return gzip.open(path, "rb")  # type: ignore[return-value]
    if head.startswith(BZ2_MAGIC):
        fh.close()
        return bz2.open(path, "rb")  # type: ignore[return-value]
    if head.startswith(XZ_MAGIC):
        fh.close()
        return lzma.open(path, "rb")  # type: ignore[return-value]
    return fh


def detect_encoding(head: bytes) -> tuple[str, int]:
    """Return ``(codec, bom_length)`` for a byte prefix."""
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8", 3
    if head.startswith(b"\xff\xfe"):
        return "utf-16-le", 2
    if head.startswith(b"\xfe\xff"):
        return "utf-16-be", 2
    sample = head[:PROBE]
    if len(sample) >= 4:
        even_nul = sample[0::2].count(0)
        odd_nul = sample[1::2].count(0)
        half = len(sample) // 2
        if odd_nul > half * 0.6 and even_nul < half * 0.1:
            return "utf-16-le", 0
        if even_nul > half * 0.6 and odd_nul < half * 0.1:
            return "utf-16-be", 0
    # Strict UTF-8 probe; drop a possibly-truncated trailing multibyte sequence first.
    probe = sample
    for cut in range(1, 4):
        if len(probe) >= cut and probe[-cut] & 0xC0 == 0xC0:
            probe = probe[:-cut]
            break
    try:
        probe.decode("utf-8")
        return "utf-8", 0
    except UnicodeDecodeError:
        return "latin-1", 0


def is_text(head: bytes) -> bool:
    """Cheap sniff: decodable as text with few control characters."""
    if not head:
        return False
    codec, bom = detect_encoding(head)
    if codec.startswith("utf-16"):
        return True
    if b"\x00" in head:
        return False
    ctrl = sum(1 for b in head[:4096] if b < 9 or (13 < b < 32 and b != 27))
    return ctrl <= len(head[:4096]) // 50


def iter_lines(path: str, *, warn=None) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, line)`` with the newline stripped. Never raises for bad bytes."""
    raw = open_binary(path)
    try:
        head = raw.read(PROBE)
        codec, bom = detect_encoding(head)
        try:
            raw.seek(bom)
        except (OSError, ValueError):
            # Non-seekable compressed streams: reopen and skip the BOM.
            raw.close()
            raw = open_binary(path)
            raw.read(bom)
        text = io.TextIOWrapper(raw, encoding=codec, errors="replace", newline="")
        lineno = 0
        while True:
            line = text.readline(MAX_LINE)
            if not line:
                return
            lineno += 1
            if not line.endswith("\n") and len(line) >= MAX_LINE:
                # Discard the remainder of an over-long line.
                dropped = 0
                while True:
                    rest = text.readline(MAX_LINE)
                    dropped += len(rest)
                    if not rest or rest.endswith("\n"):
                        break
                if warn:
                    warn(f"line {lineno}: truncated at {MAX_LINE} characters ({dropped} dropped)")
            yield lineno, line.rstrip("\r\n")
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise ParserError(f"text: {path}: {exc}") from exc
    finally:
        try:
            raw.close()
        except Exception:  # noqa: BLE001
            pass


class TextLogParser(BaseParser):
    """Line-oriented parser scaffold. Subclasses implement :meth:`parse_line`."""

    source_short = "LOG"
    #: When set, ``matches`` additionally requires this regex to match somewhere in the head.
    head_regex = None  # type: ignore[assignment]

    def matches(self, path: str, head_bytes: bytes) -> bool:
        if not is_text(head_bytes):
            return False
        if self.head_regex is not None:
            codec, bom = detect_encoding(head_bytes)
            text = head_bytes[bom:].decode(codec, "replace")
            return self.head_regex.search(text) is not None
        return super().matches(path, head_bytes)

    def begin(self, prov: Provenance) -> None:
        """Hook run before the first line (reset per-file state)."""

    def finish(self) -> Iterator[Event]:
        """Hook run after the last line (flush multi-line state)."""
        return iter(())

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:  # pragma: no cover - abstract
        raise NotImplementedError

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        self.begin(prov)
        for lineno, line in iter_lines(path, warn=self.warn):
            try:
                yield from self.parse_line(lineno, line)
            except ParserError:
                raise
            except Exception as exc:  # noqa: BLE001 - record level isolation
                self.warn(f"line {lineno}: {type(exc).__name__}: {exc}")
        try:
            yield from self.finish()
        except ParserError:
            raise
        except Exception as exc:  # noqa: BLE001
            self.warn(f"finish: {type(exc).__name__}: {exc}")


class YearTracker:
    """Year inference for year-less timestamps (syslog-style). See ``veritas.parsers.syslog``.

    Start year: ``Provenance.year_hint``, else the year of ``Provenance.mtime_ns``, else 1970
    (``source == 'default_1970'``). The year increments whenever the month goes backwards.
    """

    def __init__(self, prov: Provenance):
        from datetime import datetime, timezone

        if prov.year_hint:
            self.year, self.source = int(prov.year_hint), "year_hint"
        elif prov.mtime_ns:
            self.year = datetime.fromtimestamp(prov.mtime_ns // 1_000_000_000, tz=timezone.utc).year
            self.source = "file_mtime"
        else:
            self.year, self.source = 1970, "default_1970"
        self.last_month = 0

    def year_for(self, month: int) -> int:
        if self.last_month and month < self.last_month:
            self.year += 1
        self.last_month = month
        return self.year

    def to_ns(self, month: int, day: int, hh: int, mm: int, ss: int, frac: str | None = None) -> int | None:
        from datetime import datetime, timezone

        year = self.year_for(month)
        try:
            dt = datetime(year, month, day, hh, mm, ss, tzinfo=timezone.utc)
        except ValueError:
            return None
        ns = int((frac + "000000000")[:9]) if frac else 0
        return int(dt.timestamp()) * 1_000_000_000 + ns


MONTH_ABBR = {m: i + 1 for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
