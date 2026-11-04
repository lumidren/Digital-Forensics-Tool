"""macOS persistence inventory: LaunchAgents / LaunchDaemons plists and ``backgrounditems.btm``.

* ``*.plist`` under ``LaunchAgents``/``LaunchDaemons`` (or any plist with a ``Label`` plus
  ``Program``/``ProgramArguments``): decoded with ``plistlib`` (XML or binary; plistlib refuses
  XML entity declarations) -> ``macos:launchd:entry`` with Label, Program, ProgramArguments,
  RunAtLoad, KeepAlive, StartInterval, StartCalendarInterval, WatchPaths, UserName, Disabled.
  ``attrs.suspicious`` flags programs in /tmp, /Users/Shared, hidden paths or interpreter one-liners.
* ``backgrounditems.btm`` (Login Items, macOS 10.13-12): an NSKeyedArchiver plist whose objects
  include *bookmark* blobs (``book`` magic). The target path is resolved through the bookmark TOC
  (key 0x1004, path components array); all UTF-8 string (0x0101) and URL (0x0901) items are also
  reported as ``path_components`` / ``urls``. If the TOC is unusable the first contiguous run of
  string items is used instead.
  -> ``macos:background_items:entry``.

Both are inventory facts: ``Not a time`` unless ``Provenance.mtime_ns`` is supplied (file
modification time, Content Modification Time). Plists are capped at 16 MiB.
"""
from __future__ import annotations

import os
import plistlib
import re
import struct
from typing import Any, Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance, clip, json_safe
from veritas.timeline.schema import Desc, Event

MAX_PLIST = 16 * 1024 * 1024
KEYS = ("Label", "Program", "ProgramArguments", "RunAtLoad", "KeepAlive", "StartInterval", "StartCalendarInterval",
        "WatchPaths", "QueueDirectories", "UserName", "GroupName", "Disabled", "LaunchOnlyOnce", "LimitLoadToSessionType",
        "EnvironmentVariables", "WorkingDirectory", "StandardOutPath", "StandardErrorPath", "MachServices", "Sockets")
SUSPICIOUS = re.compile(r"(^|/)(tmp|private/tmp|Users/Shared|var/tmp)/|/\.[^/]+|\b(curl|wget|osascript|python[23]?|perl|ruby|bash|sh|zsh)\b.*(-c|-e)\b|base64",
                        re.I)


def _load_plist(path: str) -> Any:
    if os.path.getsize(path) > MAX_PLIST:
        raise ParserError("plist: larger than 16 MiB")
    with open(path, "rb") as fh:
        data = fh.read(MAX_PLIST + 1)
    try:
        return plistlib.loads(data)
    except Exception as exc:  # noqa: BLE001 - malformed plist from evidence
        raise ParserError(f"plist: {type(exc).__name__}: {exc}") from exc


class LaunchdPlistParser(BaseParser):
    name = "launchd_plist"
    version = "1.0"
    source_short = "PLIST"
    source_long = "launchd plist"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        p = path.replace("\\", "/")
        if not p.lower().endswith(".plist"):
            return False
        if "/LaunchAgents/" in p or "/LaunchDaemons/" in p:
            return True
        return (head_bytes.startswith(b"bplist00") or b"<plist" in head_bytes[:512]) and b"Label" in head_bytes and (
            b"ProgramArguments" in head_bytes or b"Program" in head_bytes)

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        obj = _load_plist(path)
        if not isinstance(obj, dict) or "Label" not in obj:
            raise ParserError("launchd_plist: no Label key")
        attrs: dict[str, Any] = {}
        for k in KEYS:
            if k in obj:
                attrs[_snake(k)] = json_safe(obj[k])
        args = obj.get("ProgramArguments") if isinstance(obj.get("ProgramArguments"), list) else []
        program = obj.get("Program") or (args[0] if args else None)
        cmd = " ".join(str(a) for a in ([program] if obj.get("Program") else []) + [str(a) for a in args])
        attrs["command_line"] = clip(cmd)
        attrs["suspicious"] = bool(SUSPICIOUS.search(cmd))
        p = path.replace("\\", "/")
        attrs["scope"] = "daemon" if "/LaunchDaemons/" in p else ("agent" if "/LaunchAgents/" in p else None)
        ts = prov.mtime_ns
        msg = f"Label: {obj.get('Label')} Program: {program} RunAtLoad: {obj.get('RunAtLoad')}"
        yield self.event("macos:launchd:entry", Desc.MODIFICATION if ts else Desc.NOT_A_TIME, msg, ts, attrs=attrs)


def _bookmark_strings(blob: bytes) -> tuple[list[str], list[str], list[str]]:
    """Return (all string items, url items, first contiguous run of string items = path)."""
    runs: list[list[str]] = []
    last_end = -1
    comps: list[str] = []
    urls: list[str] = []
    if not blob.startswith(b"book") or len(blob) < 64:
        return comps, urls, []
    # Items: u32 length | u32 type | data (padded to 4). Scan every 4-byte aligned position.
    pos = 0x30
    seen = set()
    while pos + 8 <= len(blob):
        length, typ = struct.unpack_from("<II", blob, pos)
        if typ in (0x0101, 0x0901) and 0 < length <= 4096 and pos + 8 + length <= len(blob):
            raw = blob[pos + 8:pos + 8 + length]
            try:
                s = raw.decode("utf-8")
            except UnicodeDecodeError:
                pos += 4
                continue
            if s.isprintable() and (pos, s) not in seen:
                seen.add((pos, s))
                (urls if typ == 0x0901 else comps).append(s)
                if typ == 0x0101:
                    if pos == last_end and runs:
                        runs[-1].append(s)
                    else:
                        runs.append([s])
                pos += 8 + length + ((-length) % 4)
                last_end = pos
                continue
        pos += 4
    return comps, urls, (runs[0] if runs else [])


def _bookmark_path_from_toc(blob: bytes) -> list[str] | None:
    """Resolve the path-components array (TOC key 0x1004) of a CFURL bookmark.

    Layout: ``book`` | u32 size | u32 version | u32 header_size | ...; at ``header_size`` a u32
    offset (relative to header_size) of the first TOC: u32 toc_size | u32 0xfffffffe | u32 id |
    u32 next_toc | u32 count | count * (u32 key, u32 data_offset, u32 reserved). Data offsets
    are relative to header_size; an array item (type 0x0601) lists u32 offsets of string items
    (type 0x0101). Every read is bounds-checked; returns None when anything is inconsistent.
    """
    try:
        hs = struct.unpack_from("<I", blob, 12)[0]
        toc = hs + struct.unpack_from("<I", blob, hs)[0]
        seen = set()
        while 0 < toc < len(blob) - 20 and toc not in seen and len(seen) < 32:
            seen.add(toc)
            _size, magic, _ident, nxt, count = struct.unpack_from("<IIIII", blob, toc)
            if magic != 0xFFFFFFFE or count > 4096:
                return None
            for i in range(count):
                key, off, _ = struct.unpack_from("<III", blob, toc + 20 + 12 * i)
                if key != 0x1004:
                    continue
                length, typ = struct.unpack_from("<II", blob, hs + off)
                if typ != 0x0601 or length % 4 or length > 4096:
                    return None
                out = []
                for j in range(length // 4):
                    so = struct.unpack_from("<I", blob, hs + off + 8 + 4 * j)[0]
                    sl, st = struct.unpack_from("<II", blob, hs + so)
                    if st != 0x0101 or sl > 4096:
                        return None
                    out.append(blob[hs + so + 8:hs + so + 8 + sl].decode("utf-8", "replace"))
                return out
            toc = hs + nxt if nxt else 0
    except struct.error:
        return None
    return None


class BackgroundItemsParser(BaseParser):
    name = "macos_background_items"
    version = "1.0"
    source_short = "PLIST"
    source_long = "backgrounditems.btm"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return path.lower().endswith(".btm") and head_bytes.startswith(b"bplist00")

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        obj = _load_plist(path)
        objects = obj.get("$objects") if isinstance(obj, dict) else None
        if not isinstance(objects, list):
            raise ParserError("btm: not an NSKeyedArchiver plist")
        ts = prov.mtime_ns
        index = 0
        for i, o in enumerate(objects[:100000]):
            blob = None
            if isinstance(o, (bytes, bytearray)) and bytes(o[:4]) == b"book":
                blob = bytes(o)
            elif isinstance(o, dict) and isinstance(o.get("NS.data"), (bytes, bytearray)) and bytes(o["NS.data"][:4]) == b"book":
                blob = bytes(o["NS.data"])
            if blob is None:
                continue
            try:
                comps, urls, path_comps = _bookmark_strings(blob)
                path_comps = _bookmark_path_from_toc(blob) or path_comps
            except struct.error as exc:
                self.warn(f"object {i}: {exc}")
                continue
            target = "/" + "/".join(path_comps[:64]) if path_comps else None
            attrs = {"object_index": i, "path_components": comps[:256], "urls": urls[:64], "target_path": clip(target),
                     "suspicious": bool(target and SUSPICIOUS.search(target))}
            index += 1
            yield self.event("macos:background_items:entry", Desc.MODIFICATION if ts else Desc.NOT_A_TIME,
                             f"Login item bookmark: {target or (urls[0] if urls else '')}", ts, offset=i, attrs=attrs)
        if index == 0:
            self.warn("btm: no bookmark blobs found")


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


PARSERS = [LaunchdPlistParser, BackgroundItemsParser]
