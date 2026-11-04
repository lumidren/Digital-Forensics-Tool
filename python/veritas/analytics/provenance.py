"""File provenance graph: where a file came from and what happened to it.

Nodes are file paths (normalized, lower-cased). Edges come from browser downloads (URL -> path),
Zone.Identifier ADS (URL -> path), email attachments (message -> path), archive extraction
(USN create inside a folder shortly after an archive was opened), LNK/jump list opens, prefetch
execution, USN rename/delete, and recycle bin records.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from ..timeline.store import StoredEvent
from .findings import Finding, mk_finding

EXEC_EXT = re.compile(r"(?i)\.(exe|dll|scr|ps1|bat|cmd|vbs|js|jse|hta|msi|jar|lnk|iso|img|vhd|docm|xlsm|pptm)$")


_VOLUME_PREFIX = re.compile(r"^(?:\\\\\?\\[a-z]:|[a-z]:|\\volume\{[^}]*\}|\\device\\harddiskvolume\d+)", re.I)


def norm(p: str) -> str:
    r"""Lower-case, backslashes, and the drive/volume prefix removed so that prefetch
    (``\VOLUME{guid}\...``), kernel (``\Device\HarddiskVolume2\...``) and Win32 (``C:\...``)
    spellings of one file share a key."""
    q = (p or "").replace("/", "\\").strip().strip('"').lower()
    return _VOLUME_PREFIX.sub("", q)


@dataclass(slots=True)
class Node:
    path: str
    origin: str | None = None
    origin_kind: str | None = None
    events: dict[str, list[int]] = field(default_factory=lambda: defaultdict(list))
    first_ns: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "origin": self.origin, "origin_kind": self.origin_kind, "events": {k: sorted(v) for k, v in sorted(self.events.items())}, "first_ns": self.first_ns}


def build(events: Iterable[StoredEvent]) -> dict[str, Node]:
    nodes: dict[str, Node] = {}

    def node(p: str) -> Node:
        n = norm(p)
        return nodes.setdefault(n, Node(path=n))

    def touch(n: Node, kind: str, se: StoredEvent) -> None:
        n.events[kind].append(se.id)
        t = se.event.timestamp
        if t is not None and (n.first_ns is None or t < n.first_ns):
            n.first_ns = t

    for se in events:
        e = se.event
        a = e.attrs
        dt = e.data_type
        if dt in ("chrome:history:file_downloaded", "firefox:downloads:download", "edge:history:file_downloaded"):
            p = str(a.get("full_path") or a.get("target_path") or a.get("path") or "")
            if p:
                n = node(p)
                n.origin, n.origin_kind = str(a.get("url") or a.get("source_url") or ""), "browser_download"
                touch(n, "downloaded", se)
        elif dt == "fs:stat:ntfs" and str(a.get("attribute_name") or a.get("name") or "").lower().endswith(":zone.identifier"):
            base = str(a.get("path") or e.evidence_path).split(":zone.identifier")[0]
            n = node(base)
            if a.get("host_url") or a.get("referrer_url"):
                n.origin, n.origin_kind = str(a.get("host_url") or a.get("referrer_url")), "mark_of_the_web"
            touch(n, "zone_identifier", se)
        elif dt in ("pst:message", "mbox:message", "msg:message") and a.get("attachments"):
            for att in a.get("attachments") or []:
                n = node(str(att))
                n.origin, n.origin_kind = str(a.get("sender") or a.get("from") or ""), "email_attachment"
                touch(n, "attached", se)
        elif dt == "fs:ntfs:usn_change":
            p = str(a.get("path") or a.get("filename") or "")
            reasons = str(a.get("update_reason_flags") or a.get("reason") or "")
            if p:
                n = node(p)
                for r, kind in (("FILE_CREATE", "created"), ("FILE_DELETE", "deleted"), ("RENAME_NEW_NAME", "renamed_to"), ("RENAME_OLD_NAME", "renamed_from"), ("DATA_OVERWRITE", "modified"), ("DATA_EXTEND", "modified")):
                    if r in reasons:
                        touch(n, kind, se)
        elif dt == "windows:prefetch:execution":
            for p in a.get("mapped_files") or []:
                if EXEC_EXT.search(str(p)) and str(a.get("executable") or "").lower() in str(p).lower():
                    touch(node(str(p)), "executed", se)
            exe = str(a.get("executable") or "")
            if exe:
                touch(node(exe), "executed", se)
        elif dt in ("windows:lnk:link", "windows:jump_list:automatic_destination", "windows:jump_list:custom_destination"):
            p = str(a.get("local_path") or a.get("path") or a.get("link_target") or "")
            if p:
                touch(node(p), "opened", se)
        elif dt in ("windows:metadata:deleted_item", "windows:recyclebin:record", "recycle_bin:info2", "windows:recycle_bin"):
            p = str(a.get("original_filename") or a.get("original_path") or a.get("path") or "")
            if p:
                touch(node(p), "recycled", se)
        elif dt in ("windows:registry:amcache", "windows:registry:appcompatcache", "windows:registry:bam"):
            p = str(a.get("full_path") or a.get("path") or "")
            if p:
                touch(node(p), "inventoried", se)
    return nodes


class FileProvenanceRule:
    name = "file_provenance"

    def run(self, events: Iterable[StoredEvent]) -> Iterator[Finding]:
        cached = list(events)
        by_id = {se.id: se for se in cached}
        for path, n in sorted(build(cached).items()):
            if n.origin_kind and EXEC_EXT.search(path) and ("executed" in n.events or "opened" in n.events or "inventoried" in n.events):
                ids = [i for ids in n.events.values() for i in ids]
                evs = [by_id[i] for i in ids if i in by_id]
                yield mk_finding(self.name, f"Downloaded or attached executable later used: {path.rsplit(chr(92), 1)[-1]}", f"{path} originated from {n.origin_kind} ({n.origin}) and shows {', '.join(sorted(n.events))}.", "high", 0.8, "initial-access", evs, ["T1204.002", "T1105"], n.to_dict())
