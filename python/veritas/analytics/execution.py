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

# Tools matched by name prefix, so installers and renamed builds are caught too
# (e.g. CAIN25B45.EXE, ETHEREAL-SETUP-0.10.6.EXE, NETSTUMBLERINSTALLER_0_4_0.EXE).
SUSPICIOUS_PREFIXES: tuple[tuple[str, str, str], ...] = (
    ("cain", "T1040", "high"),            # Cain & Abel: sniffing, ARP poisoning, password cracking
    ("abel", "T1003", "high"),
    ("ethereal", "T1040", "high"),        # packet capture
    ("wireshark", "T1040", "medium"),
    ("tshark", "T1040", "medium"),
    ("windump", "T1040", "high"),
    ("rawcap", "T1040", "high"),
    ("netstumbler", "T1040", "high"),     # wireless network discovery
    ("airsnort", "T1040", "high"),
    ("aircrack", "T1110", "high"),
    ("kismet", "T1040", "high"),
    ("lookatlan", "T1046", "high"),       # LAN host and service discovery
    ("nmap", "T1046", "high"),
    ("zenmap", "T1046", "high"),
    ("superscan", "T1046", "high"),
    ("angryip", "T1046", "medium"),
    ("advanced_ip_scanner", "T1046", "medium"),
    ("netcat", "T1095", "high"),
    ("pwdump", "T1003", "critical"),
    ("fgdump", "T1003", "critical"),
    ("gsecdump", "T1003", "critical"),
    ("wce", "T1003", "critical"),
    ("john", "T1110", "high"),
    ("hashcat", "T1110", "high"),
    ("l0phtcrack", "T1110", "high"),
    ("123wasp", "T1555", "high"),        # password recovery
    ("anonymizer", "T1090", "medium"),
    ("tor", "T1090.003", "medium"),
    ("psiphon", "T1090", "medium"),
)

_BASENAME = re.compile(r"[\\/]([^\\/]+)$")


def tool_family(name: str) -> tuple[str, str, str] | None:
    """(family, technique, severity) for a known dual-use or offensive tool, by exact name or prefix.

    The family groups every spelling of one tool (executable, installer, shortcut, prefetch names
    truncated at 29 characters) into a single finding.
    """
    if name in SUSPICIOUS:
        tech, sev = SUSPICIOUS[name]
        return name.rsplit(".", 1)[0], tech, sev
    stem = name.rsplit(".", 1)[0] if not name.endswith(".lnk") else name[:-4]
    stem = stem.replace(" ", "")
    for prefix, tech, sev in SUSPICIOUS_PREFIXES:
        if stem == prefix or stem.startswith(prefix) and (prefix not in ("tor", "john", "wce", "abel") or stem == prefix):
            return prefix, tech, sev
    return None


def suspicious(name: str) -> tuple[str, str] | None:
    """(technique, severity) for a known dual-use or offensive tool, by exact name or prefix."""
    f = tool_family(name)
    return (f[1], f[2]) if f else None


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
        families: dict[str, list[tuple[str, ExecutionRow, str, str]]] = defaultdict(list)
        for name, row in sorted(rows.items()):
            fam = tool_family(name)
            if fam:
                families[fam[0]].append((name, row, fam[1], fam[2]))
        order = ("info", "low", "medium", "high", "critical")
        for family, members in sorted(families.items()):
            evs = [by_id[i] for _, row, _, _ in members for ids in row.sources.values() for i in ids if i in by_id]
            sources = sorted({s for _, row, _, _ in members for s in row.sources})
            proven = any(row.proves_execution() for _, row, _, _ in members)
            sev = max((m[3] for m in members), key=order.index)
            techs = sorted({m[2] for m in members})
            names = [m[0] for m in members]
            first = min((row.first_ns for _, row, _, _ in members if row.first_ns is not None), default=None)
            last = max((row.last_ns for _, row, _, _ in members if row.last_ns is not None), default=None)
            proof = "proven" if proven else "presence only (ShimCache/Amcache do not prove execution)"
            yield mk_finding(
                self.name, f"Dual-use tool observed: {family}",
                f"{family} appears as {', '.join(names)} in {', '.join(sources)}; execution {proof}.",
                sev if sev != "info" else "low", 0.85 if proven else 0.55, "execution", evs, techs,
                {"family": family, "names": names, "first_ns": first, "last_ns": last, "rows": [row.to_dict() for _, row, _, _ in members]},
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
