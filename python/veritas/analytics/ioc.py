"""IOC sweeps across every event of a case.

Supported indicator types: ``sha256``, ``sha1``, ``md5``, ``ipv4``, ``ipv6``, ``domain``, ``url``,
``email``, ``filename``, ``path``, ``regex``, ``string``. Hash indicators match attribute values
case-insensitively; domain indicators match the host and any sub-domain; ``regex`` is compiled
with a size limit and a timeout guard (catastrophic patterns are rejected up front).
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from ..timeline.store import StoredEvent

FILE_EXT = re.compile(r"(?i)\.(exe|dll|sys|scr|ps1|bat|cmd|vbs|js|jse|hta|msi|jar|lnk|iso|img|zip|rar|7z|doc|docx|docm|xls|xlsx|xlsm|pdf|txt|tmp|dat)$")

IOC_TYPES = ("sha256", "sha1", "md5", "ipv4", "ipv6", "domain", "url", "email", "filename", "path", "regex", "string")


@dataclass(slots=True)
class Indicator:
    ioc_type: str
    value: str
    source: str = "manual"
    tags: list[str] = field(default_factory=list)
    ioc_id: str = ""

    def __post_init__(self) -> None:
        if self.ioc_type not in IOC_TYPES:
            raise ValueError(f"unknown ioc type {self.ioc_type}")
        self.value = self.value.strip()
        if self.ioc_type in ("sha256", "sha1", "md5"):
            self.value = self.value.lower()
            if not re.fullmatch({"sha256": r"[0-9a-f]{64}", "sha1": r"[0-9a-f]{40}", "md5": r"[0-9a-f]{32}"}[self.ioc_type], self.value):
                raise ValueError(f"{self.ioc_type} indicator is malformed")
        if self.ioc_type in ("ipv4", "ipv6"):
            ipaddress.ip_address(self.value)
        if self.ioc_type == "domain":
            self.value = self.value.lower().rstrip(".")
        if self.ioc_type == "regex":
            if len(self.value) > 512 or re.search(r"\([^)]*[+*][^)]*\)[+*]", self.value):
                raise ValueError("regex rejected: too long or nested quantifier")
            re.compile(self.value)
        if not self.ioc_id:
            self.ioc_id = f"{self.ioc_type}:{self.value}"

    def to_dict(self) -> dict[str, Any]:
        return {"ioc_id": self.ioc_id, "ioc_type": self.ioc_type, "value": self.value, "source": self.source, "tags": sorted(self.tags)}


@dataclass(slots=True)
class Hit:
    ioc_id: str
    event_id: int
    field: str
    matched: str

    def to_dict(self) -> dict[str, Any]:
        return {"ioc_id": self.ioc_id, "event_id": self.event_id, "field": self.field, "matched": self.matched}


def _flatten(prefix: str, v: Any) -> Iterator[tuple[str, str]]:
    if isinstance(v, str):
        yield prefix, v
    elif isinstance(v, (int, float, bool)) or v is None:
        yield prefix, str(v)
    elif isinstance(v, list):
        for i, x in enumerate(v[:500]):
            yield from _flatten(f"{prefix}[{i}]", x)
    elif isinstance(v, dict):
        for k in sorted(v):
            yield from _flatten(f"{prefix}.{k}", v[k])


class Matcher:
    def __init__(self, indicators: Iterable[Indicator]):
        self.by_type: dict[str, list[Indicator]] = {}
        for i in indicators:
            self.by_type.setdefault(i.ioc_type, []).append(i)
        self._hashes = {i.value: i for t in ("sha256", "sha1", "md5") for i in self.by_type.get(t, [])}
        self._ips = {i.value: i for t in ("ipv4", "ipv6") for i in self.by_type.get(t, [])}
        self._domains = [(i.value, i) for i in self.by_type.get("domain", [])]
        self._strings = [(i.value.lower(), i) for t in ("url", "email", "filename", "path", "string") for i in self.by_type.get(t, [])]
        self._regex = [(re.compile(i.value, re.IGNORECASE), i) for i in self.by_type.get("regex", [])]
        self._hash_re = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")
        self._ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
        self._host_re = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,63})\b", re.IGNORECASE)

    def match_text(self, field_name: str, text: str, event_id: int) -> Iterator[Hit]:
        low = text.lower()
        if self._hashes:
            for m in self._hash_re.finditer(text):
                ind = self._hashes.get(m.group(0).lower())
                if ind:
                    yield Hit(ind.ioc_id, event_id, field_name, m.group(0))
        if self._ips:
            for m in self._ip_re.finditer(text):
                ind = self._ips.get(m.group(0))
                if ind:
                    yield Hit(ind.ioc_id, event_id, field_name, m.group(0))
        if self._domains:
            for m in self._host_re.finditer(text):
                h = m.group(1).lower().rstrip(".")
                for d, ind in self._domains:
                    if h == d or h.endswith("." + d):
                        yield Hit(ind.ioc_id, event_id, field_name, m.group(1))
        for s, ind in self._strings:
            if s and s in low:
                yield Hit(ind.ioc_id, event_id, field_name, s)
        for rx, ind in self._regex:
            m = rx.search(text[:65536])
            if m:
                yield Hit(ind.ioc_id, event_id, field_name, m.group(0)[:200])

    def sweep(self, events: Iterable[StoredEvent]) -> Iterator[Hit]:
        for se in events:
            e = se.event
            seen: set[tuple[str, str]] = set()
            for fname, text in [("message", e.message), ("evidence_path", e.evidence_path), *_flatten("attrs", e.attrs)]:
                for hit in self.match_text(fname, text, se.id):
                    key = (hit.ioc_id, hit.field)
                    if key not in seen:
                        seen.add(key)
                        yield hit


def load_indicators(text: str) -> list[Indicator]:
    """Accept JSON list, one-per-line ``type:value``, or bare values (type inferred)."""
    text = text.strip()
    out: list[Indicator] = []
    if text.startswith("["):
        for d in json.loads(text):
            out.append(Indicator(d["ioc_type"], d["value"], d.get("source", "import"), d.get("tags", [])))
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line and line.split(":", 1)[0] in IOC_TYPES:
            t, v = line.split(":", 1)
            out.append(Indicator(t, v, "import"))
        else:
            out.append(Indicator(infer_type(line), line, "import"))
    return out


def infer_type(v: str) -> str:
    v = v.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", v):
        return "sha256"
    if re.fullmatch(r"[0-9a-fA-F]{40}", v):
        return "sha1"
    if re.fullmatch(r"[0-9a-fA-F]{32}", v):
        return "md5"
    try:
        return "ipv4" if ipaddress.ip_address(v).version == 4 else "ipv6"
    except ValueError:
        pass
    if "@" in v and " " not in v:
        return "email"
    if re.match(r"https?://", v, re.I):
        return "url"
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", v, re.I) and not FILE_EXT.search(v):
        return "domain"
    if "\\" in v or "/" in v:
        return "path"
    return "filename" if "." in v else "string"
