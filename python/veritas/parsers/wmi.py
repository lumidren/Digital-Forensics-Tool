"""WMI repository persistence hunting (``wbem\\Repository\\OBJECTS.DATA``).

This is deliberately *not* a full CIM repository parser (page map / index B-tree walking).
It is a carving-style scanner, in the spirit of PyWMIPersistenceFinder:

1. The file is memory-mapped (never read wholesale) and scanned for class-name occurrences
   in both ASCII and UTF-16LE: ``__EventFilter``, ``CommandLineEventConsumer``,
   ``ActiveScriptEventConsumer``, ``NTEventLogEventConsumer``, ``LogFileEventConsumer``,
   ``SMTPEventConsumer``, ``__FilterToConsumerBinding``.
2. Around each hit a window (512 bytes before, up to 8 KiB after but never past the next
   class-name hit) is cut and printable strings
   (ASCII and UTF-16LE, >= 4 characters) are extracted in file order.
3. Heuristics pick the properties: a WQL ``SELECT ... FROM`` string is the filter ``Query``;
   ``VBScript``/``JScript`` mark ``ScriptingEngine`` and the first following non-identifier string
   becomes ``ScriptText``; a string that looks like a command line (``.exe``, ``cmd``, ``powershell``,
   a path) is ``CommandLineTemplate``; the first identifier-like string that is not a class
   name, namespace or keyword is ``Name``.
4. Bindings are recovered anywhere in the file by the reference strings
   ``__EventFilter.Name="X"`` and ``<Consumer>.Name="Y"`` that WMI stores in the binding instance.

Results are inventory facts with no reliable timestamp: ``Not a time`` events with data types
``wmi:persistence:filter``, ``wmi:persistence:consumer`` and ``wmi:persistence:binding``,
deduplicated on (kind, class, name, payload). Every carved hit records its file offset.
False positives are possible (the class *definitions* themselves also contain these names);
definitions are recognised by the absence of any value-bearing strings and dropped.
"""
from __future__ import annotations

import mmap
import os
import re
from typing import Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.timeline.schema import Desc, Event

CONSUMER_CLASSES = ("CommandLineEventConsumer", "ActiveScriptEventConsumer", "NTEventLogEventConsumer",
                    "LogFileEventConsumer", "SMTPEventConsumer")
FILTER_CLASS = "__EventFilter"
BINDING_CLASS = "__FilterToConsumerBinding"
ALL_CLASSES = (FILTER_CLASS, BINDING_CLASS) + CONSUMER_CLASSES
KEYWORDS = {"WQL", "VBScript", "JScript", "root\\cimv2", "root\\subscription", "ROOT\\subscription", "__EventConsumer",
            "__IndicationRelated", "__SystemClass", "Name", "Query", "QueryLanguage", "CommandLineTemplate", "ScriptText",
            "ScriptingEngine", "EventNamespace", "CreatorSID", "ExecutablePath", "KillTimeout", "RunInteractively"}
WINDOW_BEFORE, WINDOW_AFTER = 512, 8192
ASCII_STR = re.compile(rb"[\x20-\x7e\t\r\n]{4,}")
UTF16_STR = re.compile(rb"(?:[\x20-\x7e\t\r\n]\x00){4,}")
QUERY = re.compile(r"(?is)^\s*select\s+.+\s+from\s+\S+")
COMMANDISH = re.compile(r"(?i)(\.exe\b|\.ps1\b|\.bat\b|\.cmd\b|\.vbs\b|powershell|cmd(\.exe)?\s*/c|rundll32|mshta|wscript|cscript|\\\\|[a-z]:\\)")
IDENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_ .\-{}]{1,127}$")
FILTER_REF = re.compile(rb'__EventFilter\.Name="([^"\x00]{1,256})"')
CONSUMER_REF = re.compile(rb'(\w{0,40}EventConsumer)\.Name="([^"\x00]{1,256})"')
FILTER_REF16 = re.compile('__EventFilter.Name="'.encode("utf-16-le") + rb'((?:[^"\x00]\x00){1,256})' + '"'.encode("utf-16-le"))
CONSUMER_REF16 = re.compile(rb'((?:\w\x00){0,40}E\x00v\x00e\x00n\x00t\x00C\x00o\x00n\x00s\x00u\x00m\x00e\x00r\x00)'
                            + '.Name="'.encode("utf-16-le") + rb'((?:[^"\x00]\x00){1,256})' + '"'.encode("utf-16-le"))
MAX_HITS = 100_000


def strings(buf: bytes) -> list[tuple[int, str]]:
    out = [(m.start(), m.group().decode("ascii", "replace").strip()) for m in ASCII_STR.finditer(buf)]
    out += [(m.start(), m.group().decode("utf-16-le", "replace").strip()) for m in UTF16_STR.finditer(buf)]
    out.sort()
    return [(o, s[:65536]) for o, s in out if len(s) >= 4]


class WmiPersistenceParser(BaseParser):
    name = "wmi_persistence"
    version = "1.0"
    source_short = "WMI"
    source_long = "WMI repository persistence scan"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return path.replace("\\", "/").rsplit("/", 1)[-1].upper() == "OBJECTS.DATA"

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        size = os.path.getsize(path)
        if size == 0:
            raise ParserError("wmi: empty file")
        with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            seen: set[tuple] = set()
            hits: list[tuple[int, str]] = []
            for cls in ALL_CLASSES:
                for pattern in (cls.encode("ascii"), cls.encode("utf-16-le")):
                    start = 0
                    while len(hits) < MAX_HITS:
                        idx = mm.find(pattern, start)
                        if idx < 0:
                            break
                        # "__EventFilter" is a prefix of nothing else, but CommandLineEventConsumer
                        # also contains "EventConsumer"; exact class patterns avoid overlap.
                        hits.append((idx, cls))
                        start = idx + len(pattern)
            if len(hits) >= MAX_HITS:
                self.warn("wmi: hit cap reached; results truncated")
            ordered = sorted(hits)
            for i, (off, cls) in enumerate(ordered):
                try:
                    lo = max(0, off - WINDOW_BEFORE)
                    # The window ends at the next class-name hit so neighbouring records do not bleed in.
                    nxt = next((o for o, _ in ordered[i + 1:] if o > off), size)
                    window = mm[lo:min(size, off + WINDOW_AFTER, nxt)]
                    ev = self._carve(cls, off, window, off - lo)
                    if ev is None:
                        continue
                    key = (ev.data_type, ev.attrs.get("class"), ev.attrs.get("name"), ev.attrs.get("query"),
                           ev.attrs.get("command_line_template"), ev.attrs.get("script_text"))
                    if key in seen:
                        continue
                    seen.add(key)
                    yield ev
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"hit at {off:#x}: {exc}")
            yield from self._bindings(mm, seen)

    def _carve(self, cls: str, off: int, window: bytes, rel: int) -> Event | None:
        strs = [s for o, s in strings(window) if o >= rel - 8]
        values = [s for s in strs if s not in KEYWORDS and not any(c in s for c in ALL_CLASSES)]
        if cls == FILTER_CLASS:
            query = next((s for s in values if QUERY.match(s)), None)
            if not query:
                return None  # class definition or unrelated reference
            name = next((s for s in values if s != query and IDENT.match(s) and not QUERY.match(s)), None)
            ns = next((s for s in strs if s.lower().startswith("root\\")), None)
            attrs = {"class": cls, "name": name, "query": query, "query_language": "WQL", "event_namespace": ns,
                     "file_offset": off}
            return self.event("wmi:persistence:filter", Desc.NOT_A_TIME, f"WMI event filter {name}: {query}", None,
                              offset=off, attrs=attrs)
        if cls in CONSUMER_CLASSES:
            attrs = {"class": cls, "file_offset": off}
            if cls == "ActiveScriptEventConsumer":
                engine = next((s for s in strs if s in ("VBScript", "JScript")), None)
                body = [s for s in values if not IDENT.match(s) or len(s) > 40]
                if not engine and not body:
                    return None
                # ScriptText is the first non-identifier string after the engine name (falls back to
                # the first such string); taking the longest would pick up trailing garbage.
                after = strs[strs.index(engine) + 1:] if engine in strs else strs
                script = next((s for s in after if s in body), body[0] if body else None)
                attrs.update({"scripting_engine": engine, "script_text": script})
                name = next((s for s in values if IDENT.match(s) and s != script and len(s) <= 64), None)
                payload = script
            elif cls == "CommandLineEventConsumer":
                cmds = [s for s in values if COMMANDISH.search(s)]
                if not cmds:
                    return None
                attrs["command_line_template"] = cmds[0]
                exe = next((s for s in cmds if s.lower().endswith(".exe")), None)
                attrs["executable_path"] = exe
                name = next((s for s in values if IDENT.match(s) and s not in cmds and not COMMANDISH.search(s)), None)
                payload = cmds[0]
            else:
                if not values:
                    return None
                payload = max(values, key=len)
                attrs["payload"] = payload
                name = next((s for s in values if IDENT.match(s) and s != payload), None)
            attrs["name"] = name
            return self.event("wmi:persistence:consumer", Desc.NOT_A_TIME, f"WMI {cls} {name}: {payload}", None,
                              offset=off, attrs=attrs)
        return None  # bindings are recovered from reference strings below

    def _bindings(self, mm, seen: set) -> Iterator[Event]:
        data_len = len(mm)
        chunk = 16 * 1024 * 1024
        overlap = 2048
        pos = 0
        while pos < data_len:
            buf = mm[pos:min(data_len, pos + chunk + overlap)]
            for frx, crx, enc in ((FILTER_REF, CONSUMER_REF, "ascii"), (FILTER_REF16, CONSUMER_REF16, "utf-16-le")):
                for fm in frx.finditer(buf):
                    abs_off = pos + fm.start()
                    if fm.start() >= chunk and pos + chunk < data_len:
                        continue  # will be seen in the next chunk
                    near = buf[max(0, fm.start() - 1024):fm.end() + 1024]
                    cm = crx.search(near)
                    fname = fm.group(1).decode(enc, "replace")
                    ccls = cm.group(1).decode(enc, "replace") if cm else None
                    cname = cm.group(2).decode(enc, "replace") if cm else None
                    key = ("wmi:persistence:binding", ccls, fname, cname, None, None)
                    if key in seen:
                        continue
                    seen.add(key)
                    attrs = {"class": BINDING_CLASS, "filter_name": fname, "consumer_class": ccls,
                             "consumer_name": cname, "name": fname, "file_offset": abs_off}
                    yield self.event("wmi:persistence:binding", Desc.NOT_A_TIME,
                                     f"WMI binding filter {fname} -> {ccls}.{cname}", None, offset=abs_off, attrs=attrs)
            pos += chunk


PARSERS = [WmiPersistenceParser]
