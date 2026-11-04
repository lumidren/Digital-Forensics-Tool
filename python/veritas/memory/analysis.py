"""Heuristics over Volatility plugin rows: process-tree anomalies, hidden processes, unlinked
modules, injected code, process hollowing and credential-access indicators.

Input is the ``{short plugin name: rows}`` mapping produced by
:meth:`veritas.memory.volatility.MemoryReport.rows_by_short` (the rows are in Volatility's
JSON-renderer shape, so the same code serves both backends and recorded fixtures).

Every result is a *proposed* finding (docs/THREAT_MODEL.md T5.4): it states what was observed and
why it is suspicious, nothing more. Output is deterministic: findings are sorted by
``(rule, pid, key)``.
"""
from __future__ import annotations

import ntpath
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Mapping

from veritas.parsers.base import BaseParser, Provenance
from veritas.timeline.schema import Desc, Event, iso_to_ns, sorted_events

VERSION = "1.0"

# child image -> allowed parent images (lower case). Parents that normally exit (smss children)
# are only checked when the parent is still present.
EXPECTED_PARENTS: dict[str, frozenset[str]] = {
    "smss.exe": frozenset({"system", "smss.exe"}),
    "csrss.exe": frozenset({"smss.exe"}),
    "wininit.exe": frozenset({"smss.exe"}),
    "winlogon.exe": frozenset({"smss.exe"}),
    "lsass.exe": frozenset({"wininit.exe"}),
    "lsaiso.exe": frozenset({"wininit.exe"}),
    "services.exe": frozenset({"wininit.exe"}),
    "lsm.exe": frozenset({"wininit.exe"}),
    "svchost.exe": frozenset({"services.exe", "msmpeng.exe"}),
    "spoolsv.exe": frozenset({"services.exe"}),
    "taskhost.exe": frozenset({"services.exe", "svchost.exe"}),
    "taskhostw.exe": frozenset({"svchost.exe", "services.exe"}),
    "runtimebroker.exe": frozenset({"svchost.exe"}),
    "userinit.exe": frozenset({"winlogon.exe"}),
}
# Processes of which a healthy system has exactly one (per boot).
SINGLETONS = ("lsass.exe", "services.exe", "wininit.exe", "lsaiso.exe")
# Names attackers imitate; one edit away from these is a masquerading indicator.
SYSTEM_NAMES = (
    "lsass.exe", "services.exe", "svchost.exe", "csrss.exe", "smss.exe", "wininit.exe",
    "winlogon.exe", "explorer.exe", "spoolsv.exe", "taskhost.exe", "taskhostw.exe", "lsm.exe",
    "conhost.exe", "dllhost.exe", "rundll32.exe", "searchindexer.exe",
)
# Processes that legitimately hold handles to lsass.
LSASS_HANDLE_ALLOW = frozenset({
    "lsass.exe", "csrss.exe", "wininit.exe", "services.exe", "svchost.exe", "msmpeng.exe",
    "lsm.exe", "system", "wmiprvse.exe", "mssense.exe", "sense.exe", "nissrv.exe", "lsaiso.exe",
})
PROCESS_VM_READ = 0x0010
PROCESS_ALL_ACCESS_MASKS = (0x1F0FFF, 0x1FFFFF)

ATTACK = {
    "unexpected_parent": "T1036.005",
    "masquerade_name": "T1036.005",
    "duplicate_singleton": "T1036",
    "hidden_process": "T1014",
    "unlinked_module": "T1055",
    "rwx_private_memory": "T1055",
    "process_hollowing": "T1055.012",
    "lsass_handle": "T1003.001",
}


@dataclass(slots=True)
class MemoryFinding:
    rule: str
    severity: str  # low | medium | high
    title: str
    pid: int | None = None
    process: str | None = None
    timestamp: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def technique(self) -> str:
        return ATTACK.get(self.rule, "")

    def sort_key(self) -> tuple:
        return (self.rule, self.pid if self.pid is not None else -1, self.title)


# --------------------------------------------------------------------------- helpers
def _get(row: Mapping[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in row and row[k] is not None:
            return row[k]
    return None


def _int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except ValueError:
            return None
    return None


def _name(row: Mapping[str, Any]) -> str:
    v = _get(row, "ImageFileName", "Process", "COMM", "Name")
    return str(v).strip().lower() if v is not None else ""


def _pid(row: Mapping[str, Any]) -> int | None:
    return _int(_get(row, "PID", "Pid", "pid"))


def _ppid(row: Mapping[str, Any]) -> int | None:
    return _int(_get(row, "PPID", "PPid", "ppid"))


def _falsy(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("false", "0", "")
    return v is False or v == 0


def _basename(path: Any) -> str:
    if not isinstance(path, str) or not path:
        return ""
    return ntpath.basename(path.replace("/", "\\")).lower()


def _edit_distance_le1(a: str, b: str) -> bool:
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        # adjacent transposition (scvhost)
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(long_)):
        if long_[:i] + long_[i + 1:] == short:
            return True
    return False


def _name_matches(truncated: str, full: str) -> bool:
    """EPROCESS.ImageFileName is truncated to 14 characters."""
    return bool(truncated) and (truncated == full or (len(truncated) >= 14 and full.startswith(truncated)))


# --------------------------------------------------------------------------- rules
def process_tree_findings(pslist: list[dict[str, Any]]) -> Iterator[MemoryFinding]:
    by_pid: dict[int, dict[str, Any]] = {}
    for row in pslist:
        pid = _pid(row)
        if pid is not None and pid not in by_pid:
            by_pid[pid] = row
    counts: dict[str, list[int]] = {}
    for row in pslist:
        name, pid = _name(row), _pid(row)
        if not name:
            continue
        if not row.get("ExitTime"):
            counts.setdefault(name, []).append(pid if pid is not None else -1)
        ts = iso_to_ns(row["CreateTime"]) if isinstance(row.get("CreateTime"), str) else None
        allowed = EXPECTED_PARENTS.get(name)
        if allowed is not None:
            parent = by_pid.get(_ppid(row)) if _ppid(row) is not None else None
            if parent is not None:
                pname = _name(parent)
                # A recycled PPID (parent started after the child) is not an anomaly.
                p_ts = iso_to_ns(parent["CreateTime"]) if isinstance(parent.get("CreateTime"), str) else None
                recycled = ts is not None and p_ts is not None and p_ts > ts
                if pname not in allowed and not recycled:
                    yield MemoryFinding(
                        "unexpected_parent", "high",
                        f"{name} (PID {pid}) has parent {pname} (PID {_ppid(row)}); expected {', '.join(sorted(allowed))}",
                        pid, name, ts, {"ppid": _ppid(row), "parent": pname},
                    )
        for sysname in () if name in SYSTEM_NAMES else SYSTEM_NAMES:
            if _edit_distance_le1(name, sysname) and not _name_matches(name, sysname):
                yield MemoryFinding(
                    "masquerade_name", "medium", f"{name} (PID {pid}) imitates {sysname}", pid, name, ts,
                    {"imitates": sysname},
                )
                break
    for name in SINGLETONS:
        pids = sorted(counts.get(name, []))
        if len(pids) > 1:
            yield MemoryFinding(
                "duplicate_singleton", "high", f"{len(pids)} live {name} processes (PIDs {', '.join(map(str, pids))})",
                pids[0], name, None, {"pids": pids},
            )


def hidden_process_findings(pslist: list[dict[str, Any]], psscan: list[dict[str, Any]]) -> Iterator[MemoryFinding]:
    """Processes found by pool scanning that are absent from the active process list."""
    if not pslist or not psscan:
        return
    listed = {(_pid(r), _name(r), r.get("CreateTime")) for r in pslist}
    listed_pids = {_pid(r) for r in pslist}
    for row in psscan:
        if row.get("ExitTime"):
            continue  # terminated processes legitimately linger in pool memory
        key = (_pid(row), _name(row), row.get("CreateTime"))
        if key in listed or _pid(row) is None:
            continue
        ts = iso_to_ns(row["CreateTime"]) if isinstance(row.get("CreateTime"), str) else None
        sev = "high" if _pid(row) not in listed_pids else "medium"
        yield MemoryFinding(
            "hidden_process", sev,
            f"{_name(row)} (PID {_pid(row)}) found by psscan but not in the active process list",
            _pid(row), _name(row), ts, {"offset": _get(row, "Offset(V)", "Offset(P)", "Offset")},
        )


def unlinked_module_findings(ldrmodules: list[dict[str, Any]]) -> Iterator[MemoryFinding]:
    for row in ldrmodules:
        mapped = _get(row, "MappedPath")
        if not isinstance(mapped, str) or not mapped:
            continue
        in_load, in_init, in_mem = (row.get(k) for k in ("InLoad", "InInit", "InMem"))
        if in_load is None and in_mem is None:
            continue
        # The process executable is never in the init-order list, so only Load+Mem decide.
        if _falsy(in_load) and _falsy(in_mem):
            yield MemoryFinding(
                "unlinked_module", "high",
                f"{_name(row)} (PID {_pid(row)}) maps {mapped} but it is unlinked from the PEB module lists",
                _pid(row), _name(row), None,
                {"base": _get(row, "Base"), "mapped_path": mapped, "in_load": in_load, "in_init": in_init, "in_mem": in_mem},
            )


def injection_findings(malfind: list[dict[str, Any]]) -> Iterator[MemoryFinding]:
    for row in malfind:
        prot = str(_get(row, "Protection") or "")
        if "EXECUTE_READWRITE" not in prot and "rwx" not in prot.lower():
            continue
        private = _get(row, "PrivateMemory")
        if private is not None and _falsy(private):
            continue
        hexdump = str(_get(row, "Hexdump") or "").replace(" ", "").replace("\n", "").lower()
        has_mz = hexdump.startswith("4d5a")
        start = _get(row, "Start VPN", "Start")
        yield MemoryFinding(
            "rwx_private_memory", "high" if has_mz else "medium",
            f"{_name(row)} (PID {_pid(row)}) has private {prot} memory at {start}"
            + (" starting with an MZ header" if has_mz else ""),
            _pid(row), _name(row), None,
            {"start": start, "end": _get(row, "End VPN", "End"), "protection": prot, "tag": _get(row, "Tag"), "mz_header": has_mz},
        )


def hollowing_findings(
    pslist: list[dict[str, Any]],
    dlllist: list[dict[str, Any]],
    ldrmodules: list[dict[str, Any]],
    hollow: list[dict[str, Any]],
) -> Iterator[MemoryFinding]:
    for row in hollow:
        yield MemoryFinding(
            "process_hollowing", "high",
            f"{_name(row)} (PID {_pid(row)}): {_get(row, 'Notes') or 'reported by hollowprocesses'}",
            _pid(row), _name(row), None, {"source": "hollowprocesses", "notes": _get(row, "Notes")},
        )
    reported = {_pid(r) for r in hollow}
    # PEB image path (first dlllist entry of a process is the executable) vs the file the VAD
    # at the same base actually maps (ldrmodules MappedPath).
    exe_by_pid: dict[int, dict[str, Any]] = {}
    for row in dlllist:
        pid = _pid(row)
        if pid is not None and pid not in exe_by_pid:
            exe_by_pid[pid] = row
    mapped_by_key: dict[tuple[int, int], Any] = {}
    for row in ldrmodules:
        pid, base = _pid(row), _int(_get(row, "Base"))
        if pid is not None and base is not None:
            mapped_by_key[(pid, base)] = _get(row, "MappedPath")
    names = {_pid(r): _name(r) for r in pslist}
    for pid in sorted(exe_by_pid):
        if pid in reported:
            continue
        row = exe_by_pid[pid]
        peb_path = _get(row, "Path", "FullDllName")
        base = _int(_get(row, "Base"))
        peb_name = _basename(peb_path)
        reasons = []
        if base is not None and (pid, base) in mapped_by_key:
            vad_name = _basename(mapped_by_key[(pid, base)])
            if not vad_name:
                reasons.append("image base is not backed by a mapped file")
            elif peb_name and vad_name != peb_name:
                reasons.append(f"PEB path {peb_name} but VAD maps {vad_name}")
        eproc = names.get(pid) or _name(row)
        if peb_name and eproc and not _name_matches(eproc, peb_name) and not peb_name.startswith(eproc):
            reasons.append(f"EPROCESS name {eproc} differs from PEB image {peb_name}")
        if reasons:
            yield MemoryFinding(
                "process_hollowing", "high", f"{eproc or peb_name} (PID {pid}): " + "; ".join(reasons),
                pid, eproc or peb_name, None, {"peb_path": peb_path, "base": base, "reasons": reasons},
            )


def credential_access_findings(handles: list[dict[str, Any]], pslist: list[dict[str, Any]]) -> Iterator[MemoryFinding]:
    lsass_pids = {_pid(r) for r in pslist if _name(r) == "lsass.exe"}
    seen: set[tuple[int | None, Any]] = set()
    for row in handles:
        if str(_get(row, "Type") or "") != "Process":
            continue
        target = str(_get(row, "Name") or "").lower()
        if "lsass.exe" not in target and not any(f"pid {p}" in target or f"({p})" in target for p in lsass_pids if p is not None):
            continue
        holder = _name(row)
        if holder in LSASS_HANDLE_ALLOW:
            continue
        access = _int(_get(row, "GrantedAccess"))
        key = (_pid(row), access)
        if key in seen:
            continue
        seen.add(key)
        reads = access is not None and (access & PROCESS_VM_READ or access in PROCESS_ALL_ACCESS_MASKS)
        yield MemoryFinding(
            "lsass_handle", "high" if reads else "medium",
            f"{holder} (PID {_pid(row)}) holds a process handle to lsass.exe"
            + (f" with access 0x{access:x}" if access is not None else ""),
            _pid(row), holder, None, {"granted_access": access, "target": _get(row, "Name"), "vm_read": bool(reads)},
        )


# --------------------------------------------------------------------------- entry point
class MemoryAnalyzer(BaseParser):
    name = "memory_analysis"
    version = VERSION
    source_short = "MEMORY"
    source_long = "Veritas memory heuristics"

    def analyze(self, rows: Mapping[str, list[dict[str, Any]]]) -> list[MemoryFinding]:
        pslist = rows.get("pslist") or rows.get("pstree") or []
        dlllist = rows.get("dlllist", [])
        ldr = rows.get("ldrmodules", [])
        out: list[MemoryFinding] = []
        rules: Iterable[Iterator[MemoryFinding]] = (
            process_tree_findings(pslist),
            hidden_process_findings(pslist, rows.get("psscan", [])),
            unlinked_module_findings(ldr),
            injection_findings(rows.get("malfind", [])),
            hollowing_findings(pslist, dlllist, ldr, rows.get("hollowprocesses", [])),
            credential_access_findings(rows.get("handles", []), pslist),
        )
        for gen in rules:
            try:
                out.extend(gen)
            except Exception as exc:  # noqa: BLE001 - one rule failing must not hide others
                self.warn(f"memory analysis rule failed: {type(exc).__name__}: {exc}")
        return sorted(out, key=MemoryFinding.sort_key)

    def to_events(self, findings: Iterable[MemoryFinding], provenance: Provenance | None = None) -> list[Event]:
        if provenance is not None:
            self._prov = provenance
        events = []
        for i, f in enumerate(findings):
            events.append(self.event(
                "memory:finding", Desc.CREATION if f.timestamp is not None else Desc.NOT_A_TIME,
                f"[{f.severity}] {f.title}", f.timestamp, offset=i,
                attrs={"rule": f.rule, "severity": f.severity, "technique": f.technique, "pid": f.pid,
                       "process": f.process, "status": "proposed", "evidence": f.evidence},
            ))
        return sorted_events(events)
