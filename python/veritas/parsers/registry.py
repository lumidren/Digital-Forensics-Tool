"""Parser registry: every Python artifact parser, format sniffing and auto-dispatch.

``ALL_PARSERS`` is ordered from most to least specific; :func:`select` returns the first parser
whose ``matches(path, head_bytes)`` accepts the file, so specific binary/sqlite formats win over
generic text sniffers (syslog, crontab) that come last. ``head_bytes`` should be at least the
first 4 KiB of the file (:data:`HEAD_SIZE`).
"""
from __future__ import annotations

from typing import Iterator

from veritas.parsers import (
    apache, app_usage, asl, auditd, bsm, cron, email_pst, fsevents, imessage, knowledgec, launch_agents,
    launchd_log, mbox, notificationcenter, office, package_logs, powershell, quarantine, recyclebin, santa,
    setupapi, shell_history, srum, ssh, syslog, systemd_units, tcc, unified_log, utmp, appfirewall, wifi_log,
    windefender, windows_firewall, windows_timeline, wmi,
)
from veritas.parsers.base import BaseParser, ParserError, Provenance, read_head
from veritas.parsers.browsers import chromium, firefox, ie_edge_legacy
from veritas.timeline.schema import Event

HEAD_SIZE = 4096

_MODULES_SPECIFIC = [
    # binary / structured formats with magic numbers or exact names
    email_pst, srum, ie_edge_legacy, recyclebin, windefender, office, asl, bsm, fsevents, utmp, wmi,
    # sqlite databases (dispatch on file name + SQLite magic)
    chromium, firefox, windows_timeline, knowledgec, quarantine, tcc, app_usage, notificationcenter, imessage,
    # plists / json exports
    launch_agents, unified_log,
    # text formats with distinctive headers
    powershell, setupapi, windows_firewall, auditd, apache, package_logs, santa, wifi_log, appfirewall,
    launchd_log, shell_history, ssh, systemd_units, mbox,
    # generic text sniffers last
    cron, syslog,
]

ALL_PARSERS: list[type[BaseParser]] = [cls for mod in _MODULES_SPECIFIC for cls in mod.PARSERS]


def parser_names() -> list[str]:
    return [cls.name for cls in ALL_PARSERS]


def get(name: str) -> type[BaseParser]:
    for cls in ALL_PARSERS:
        if cls.name == name:
            return cls
    raise KeyError(name)


def select_all(path: str, head: bytes) -> list[BaseParser]:
    """All parsers that accept the file, most specific first."""
    out = []
    for cls in ALL_PARSERS:
        parser = cls()
        try:
            if parser.matches(path, head):
                out.append(parser)
        except Exception:  # noqa: BLE001 - a sniffer must never break dispatch
            continue
    return out


def _decompressed_head(head: bytes, path: str) -> bytes | None:
    """For gzip/bz2/xz input return the first HEAD_SIZE decompressed bytes (rotated text logs)."""
    from veritas.parsers.text_log import BZ2_MAGIC, GZIP_MAGIC, XZ_MAGIC, open_binary

    if not (head.startswith(GZIP_MAGIC) or head.startswith(BZ2_MAGIC) or head.startswith(XZ_MAGIC)):
        return None
    try:
        with open_binary(path) as fh:
            return fh.read(HEAD_SIZE)
    except Exception:  # noqa: BLE001 - corrupt archive: no decompressed view
        return None


def select(path: str, head: bytes) -> BaseParser | None:
    """The most specific parser that accepts the file, or ``None``.

    Compressed (gzip/bz2/xz) files are first offered raw (FSEvents pages are gzip files) and then
    with their decompressed head, so rotated text logs (``syslog.2.gz``) are recognised. The
    chosen text parser decompresses transparently (``text_log.open_binary``).
    """
    found = _select(path, head)
    if found is None:
        inner = _decompressed_head(head, path)
        if inner:
            found = _select(path, inner)
    return found


def _select(path: str, head: bytes) -> BaseParser | None:
    for cls in ALL_PARSERS:
        parser = cls()
        try:
            if parser.matches(path, head):
                return parser
        except Exception:  # noqa: BLE001
            continue
    return None


def parse_auto(path: str, provenance: Provenance) -> Iterator[Event]:
    """Sniff ``path``, pick a parser with :func:`select` and yield its events.

    Raises :class:`ParserError` when no parser matches (or when the chosen parser fails).
    """
    head = read_head(path, HEAD_SIZE)
    parser = select(path, head)
    if parser is None:
        raise ParserError(f"no parser matches {path}")
    yield from parser.parse(path, provenance)
