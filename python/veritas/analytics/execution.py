"""Execution-evidence correlation.

Combines prefetch (proof of execution with time), Amcache (file inventory with SHA-1),
ShimCache (presence, not execution on Win10+), BAM (per-user last execution), UserAssist (GUI
launches), Security 4688 / Sysmon 1 (process creation with parent and command line) into one
table keyed by executable base name. Each row lists which sources agree, so an examiner can
state exactly what proves execution and what only proves presence.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from ..timeline.store import StoredEvent
from .findings import Finding, mk_finding

SUSPICIOUS = {
    "mimikatz.exe": ("T1003.001", "critical"), "procdump.exe": ("T1003.001", "high"), "procdump64.exe": ("T1003.001", "high"),
    "psexec.exe": ("T1569.002", "high"), "psexesvc.exe": ("T1569.002", "high"), "paexec.exe": ("T1569.002", "high"),
    "wmic.exe": ("T1047", "medium"), "rundll32.exe": ("T1218.011", "low"), "mshta.exe": ("T1218.005", "medium"), "regsvr32.exe": ("T1218.010", "low"),
    "certutil.exe": ("T1105", "medium"), "bitsadmin.exe": ("T1105", "medium"), "powershell.exe": ("T1059.001", "info"), "pwsh.exe": ("T1059.001", "info"),
    "rclone.exe": ("T1048", "high"), "megasync.exe": ("T1048", "medium"), "7z.exe": ("T1560.001", "low"), "winrar.exe": ("T1560.001", "low"), "rar.exe": ("T1560.001", "medium"),
    "vssadmin.exe": ("T1490", "medium"), "wbadmin.exe": ("T1490", "medium"), "bcdedit.exe": ("T1490", "medium"), "nltest.exe": ("T1482", "low"), "adfind.exe": ("T1087", "high"),
    "sharphound.exe": ("T1087", "high"), "bloodhound.exe": ("T1087", "high"), "lazagne.exe": ("T1003", "high"), "netcat.exe": ("T1095", "high"), "nc.exe": ("T1095", "high"),
    "plink.exe": ("T1572", "medium"), "anydesk.exe": ("T1219", "medium"), "teamviewer.exe": ("T1219", "low"), "ngrok.exe": ("T1572", "high"), "cobaltstrike.exe": ("T1071", "critical"),
}

_BASENAME = re.compile(r"[\\/]([^\\/]+)$")


def basename(path: str) -> str:
    m = _BASENAME.search(path or "")
    return (m.group(1) if m else path or "").lower().strip('"')


@dataclass(slots=True)
class ExecutionRow:
    executable: str
    sources: dict[str, list[int]] = field(default_factory=lambda: defaultdict(list))
    first_ns: int | None = None
    last_ns: int | None = None
    paths: set[str] = field(default_factory=set)
    sha1: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)

    def proves_execution(self) -> bool:
        return any(s in self.sources for s in ("prefetch", "evtx_4688", "sysmon_1", "bam", "userassist"))

    def to_dict(self) -> dict:
        return {
            "executable": self.executable, "sources": {k: sorted(v) for k, v in sorted(self.sources.items())}, "first_ns": self.first_ns,
            "last_ns": self.last_ns, "paths": sorted(self.paths), "sha1": sorted(self.sha1), "users": sorted(self.users), "hosts": sorted(self.hosts),
            "proves_execution": self.proves_execution(),
        }


def classify(e) -> tuple[str, str] | None:
    """Return (source, executable path) for an execution-related event or None."""
    a = e.attrs
    dt = e.data_type
    if dt == "windows:prefetch:execution":
        return "prefetch", str(a.get("executable") or a.get("executable_name") or "")
    if dt == "windows:registry:appcompatcache":
        return "shimcache", str(a.get("path") or "")
    if dt in ("windows:registry:amcache", "windows:registry:amcache:programs"):
        return "amcache", str(a.get("full_path") or a.get("path") or a.get("name") or "")
    if dt == "windows:registry:bam":
        return "bam", str(a.get("path") or a.get("binary_path") or "")
    if dt == "windows:registry:userassist":
        return "userassist", str(a.get("value_name") or a.get("path") or "")
    if dt in ("windows:evtx:record", "windows:evt:record"):
        eid = a.get("event_identifier")
        prov = str(a.get("source_name") or a.get("provider") or "")
        if eid == 4688:
            return "evtx_4688", str(a.get("process_name") or a.get("new_process_name") or (a.get("event_data") or {}).get("NewProcessName") or "")
        if eid == 1 and "Sysmon" in prov:
            return "sysmon_1", str(a.get("image") or (a.get("event_data") or {}).get("Image") or "")
    return None


def correlate(events: Iterable[StoredEvent]) -> dict[str, ExecutionRow]:
    rows: dict[str, ExecutionRow] = {}
    for se in events:
        e = se.event
        c = classify(e)
        if not c:
            continue
        source, path = c
        name = basename(path)
        if not name:
            continue
        row = rows.setdefault(name, ExecutionRow(executable=name))
        row.sources[source].append(se.id)
        row.paths.add(path)
        if e.timestamp is not None:
            row.first_ns = e.timestamp if row.first_ns is None else min(row.first_ns, e.timestamp)
            row.last_ns = e.timestamp if row.last_ns is None else max(row.last_ns, e.timestamp)
        if e.attrs.get("sha1"):
            row.sha1.add(str(e.attrs["sha1"]).lower())
        if e.user:
            row.users.add(e.user)
        if e.host:
            row.hosts.add(e.host)
    return rows


class ExecutionCorrelationRule:
    name = "execution"

    def run(self, events: Iterable[StoredEvent]) -> Iterator[Finding]:
        cached = list(events)
        by_id = {se.id: se for se in cached}
        rows = correlate(cached)
        for name, row in sorted(rows.items()):
            if name in SUSPICIOUS:
                tech, sev = SUSPICIOUS[name]
                evs = [by_id[i] for ids in row.sources.values() for i in ids if i in by_id]
                proof = "proven" if row.proves_execution() else "presence only (ShimCache/Amcache do not prove execution)"
                yield mk_finding(
                    self.name, f"Dual-use tool observed: {name}",
                    f"{name} appears in {', '.join(sorted(row.sources))}; execution {proof}.",
                    sev if sev != "info" else "low", 0.85 if row.proves_execution() else 0.55, "execution", evs, [tech], row.to_dict(),
                )
        # Renamed/masquerading binaries: Amcache SHA-1 shared by two different names.
        by_hash: dict[str, set[str]] = defaultdict(set)
        for name, row in rows.items():
            for h in row.sha1:
                by_hash[h].add(name)
        for h, names in sorted(by_hash.items()):
            if len(names) > 1:
                evs = [by_id[i] for n in names for ids in rows[n].sources.values() for i in ids if i in by_id]
                yield mk_finding(self.name, f"Same binary under several names ({', '.join(sorted(names))})", f"Amcache records SHA-1 {h} for more than one file name, consistent with a renamed tool.", "medium", 0.7, "defense-evasion", evs, ["T1036"], {"sha1": h, "names": sorted(names)})
