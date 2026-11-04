"""Memory heuristics: each rule on synthetic Volatility rows, a clean baseline, and no-crash fuzzing."""
from __future__ import annotations

from hypothesis import given, settings, strategies as st

from veritas.memory.analysis import MemoryAnalyzer
from veritas.parsers.base import Provenance
from veritas.timeline.schema import Desc


def proc(pid, ppid, name, created="2024-05-01T08:00:00+00:00", exited=None, offset=None):
    return {"PID": pid, "PPID": ppid, "ImageFileName": name, "CreateTime": created, "ExitTime": exited,
            "Offset(V)": offset or pid * 0x100}


CLEAN = [
    proc(4, 0, "System"), proc(300, 4, "smss.exe"), proc(400, 300, "csrss.exe"), proc(450, 300, "wininit.exe"),
    proc(500, 450, "services.exe"), proc(510, 450, "lsass.exe"), proc(600, 500, "svchost.exe"),
    proc(700, 500, "spoolsv.exe"), proc(800, 3000, "explorer.exe"), proc(900, 600, "taskhostw.exe"),
]


def run(rows):
    a = MemoryAnalyzer()
    return a, a.analyze(rows)


def test_clean_system_has_no_findings():
    _, findings = run({"pslist": CLEAN, "psscan": CLEAN})
    assert findings == []


def test_unexpected_parent_and_recycled_ppid():
    rows = CLEAN + [proc(1000, 800, "lsass.exe", created="2024-05-01T09:00:00+00:00")]
    _, f = run({"pslist": rows})
    hits = [x for x in f if x.rule == "unexpected_parent"]
    assert len(hits) == 1 and hits[0].pid == 1000 and hits[0].technique == "T1036.005"
    # parent started after the child: PID reuse, not an anomaly
    late_parent = [proc(20, 4, "System"), proc(21, 22, "svchost.exe", created="2024-05-01T08:00:00+00:00"),
                   proc(22, 4, "cmd.exe", created="2024-05-02T08:00:00+00:00")]
    _, f = run({"pslist": late_parent})
    assert not [x for x in f if x.rule == "unexpected_parent"]


def test_duplicate_singleton_and_masquerade():
    rows = CLEAN + [proc(1100, 450, "lsass.exe"), proc(1200, 500, "scvhost.exe"), proc(1300, 800, "lsas.exe")]
    _, f = run({"pslist": rows})
    rules = {(x.rule, x.pid) for x in f}
    assert ("duplicate_singleton", 510) in rules
    assert ("masquerade_name", 1200) in rules and ("masquerade_name", 1300) in rules
    # exited duplicate does not count
    _, f = run({"pslist": CLEAN + [proc(1100, 450, "lsass.exe", exited="2024-05-01T08:01:00+00:00")]})
    assert not [x for x in f if x.rule == "duplicate_singleton"]


def test_hidden_process_ignores_exited():
    scan = CLEAN + [proc(4444, 4, "hidden.exe"), proc(4445, 4, "gone.exe", exited="2024-05-01T08:02:00+00:00")]
    _, f = run({"pslist": CLEAN, "psscan": scan})
    hidden = [x for x in f if x.rule == "hidden_process"]
    assert [h.pid for h in hidden] == [4444] and hidden[0].severity == "high"
    assert hidden[0].timestamp == 1714550400 * 10**9


def test_unlinked_module():
    ldr = [
        {"Pid": 600, "Process": "svchost.exe", "Base": 0x7FF0000, "InLoad": True, "InInit": False, "InMem": True,
         "MappedPath": "\\Windows\\System32\\svchost.exe"},
        {"Pid": 600, "Process": "svchost.exe", "Base": 0x10000000, "InLoad": False, "InInit": False, "InMem": False,
         "MappedPath": "\\Users\\x\\AppData\\evil.dll"},
        {"Pid": 600, "Process": "svchost.exe", "Base": 0x20000000, "InLoad": False, "InInit": False, "InMem": False,
         "MappedPath": ""},
    ]
    _, f = run({"pslist": CLEAN, "ldrmodules": ldr})
    hits = [x for x in f if x.rule == "unlinked_module"]
    assert len(hits) == 1 and "evil.dll" in hits[0].title


def test_rwx_private_memory_severity():
    mal = [
        {"PID": 600, "Process": "svchost.exe", "Start VPN": 0x1000, "Protection": "PAGE_EXECUTE_READWRITE",
         "PrivateMemory": 1, "Hexdump": "4d 5a 90 00"},
        {"PID": 700, "Process": "spoolsv.exe", "Start VPN": 0x2000, "Protection": "PAGE_EXECUTE_READWRITE",
         "PrivateMemory": 1, "Hexdump": "fc e8 89 00"},
        {"PID": 700, "Process": "spoolsv.exe", "Start VPN": 0x3000, "Protection": "PAGE_EXECUTE_READ",
         "PrivateMemory": 1, "Hexdump": "00"},
        {"PID": 700, "Process": "spoolsv.exe", "Start VPN": 0x4000, "Protection": "PAGE_EXECUTE_READWRITE",
         "PrivateMemory": 0, "Hexdump": "00"},
    ]
    _, f = run({"malfind": mal})
    hits = sorted((x.pid, x.severity) for x in f if x.rule == "rwx_private_memory")
    assert hits == [(600, "high"), (700, "medium")]


def test_hollowing_peb_vs_vad():
    dll = [{"PID": 600, "Process": "svchost.exe", "Base": 0x400000, "Path": "C:\\Windows\\System32\\svchost.exe"},
           {"PID": 600, "Process": "svchost.exe", "Base": 0x7FF00000, "Path": "C:\\Windows\\System32\\ntdll.dll"},
           {"PID": 700, "Process": "spoolsv.exe", "Base": 0x500000, "Path": "C:\\Windows\\System32\\spoolsv.exe"}]
    ldr = [{"Pid": 600, "Process": "svchost.exe", "Base": 0x400000, "InLoad": True, "InInit": False, "InMem": True,
            "MappedPath": "\\Users\\Public\\payload.exe"},
           {"Pid": 700, "Process": "spoolsv.exe", "Base": 0x500000, "InLoad": True, "InInit": False, "InMem": True,
            "MappedPath": "\\Windows\\System32\\spoolsv.exe"}]
    _, f = run({"pslist": CLEAN, "dlllist": dll, "ldrmodules": ldr,
                "hollowprocesses": [{"PID": 900, "Process": "taskhostw.exe", "Notes": "Invalid VAD protection"}]})
    hits = {x.pid: x for x in f if x.rule == "process_hollowing"}
    assert set(hits) == {600, 900}
    assert "payload.exe" in hits[600].title and hits[600].technique == "T1055.012"


def test_lsass_handles():
    handles = [
        {"PID": 500, "Process": "services.exe", "Type": "Process", "GrantedAccess": 0x1FFFFF, "Name": "lsass.exe Pid 510"},
        {"PID": 4000, "Process": "procdump64.exe", "Type": "Process", "GrantedAccess": "0x1410", "Name": "lsass.exe Pid 510"},
        {"PID": 4001, "Process": "notepad.exe", "Type": "Process", "GrantedAccess": 0x1000, "Name": "lsass.exe Pid 510"},
        {"PID": 4002, "Process": "notepad.exe", "Type": "File", "GrantedAccess": 0x1FFFFF, "Name": "lsass.exe"},
    ]
    _, f = run({"pslist": CLEAN, "handles": handles})
    hits = {x.pid: x.severity for x in f if x.rule == "lsass_handle"}
    assert hits == {4000: "high", 4001: "medium"}


def test_findings_events_are_proposed_and_deterministic():
    rows = {"pslist": CLEAN + [proc(1100, 450, "lsass.exe")], "psscan": CLEAN + [proc(4444, 4, "h.exe")]}
    a1, f1 = run(rows)
    a2, f2 = run(rows)
    e1 = a1.to_events(f1, Provenance(evidence_path="m.raw"))
    e2 = a2.to_events(f2, Provenance(evidence_path="m.raw"))
    assert [e.to_json() for e in e1] == [e.to_json() for e in e2]
    assert all(e.attrs["status"] == "proposed" and e.data_type == "memory:finding" for e in e1)
    assert any(e.timestamp_desc == Desc.CREATION for e in e1)


cell = st.one_of(st.none(), st.booleans(), st.integers(-5, 2**40), st.text(max_size=20),
                 st.sampled_from(["lsass.exe", "svchost.exe", "PAGE_EXECUTE_READWRITE", "Process", "0x1fffff",
                                  "2024-05-01T08:00:00+00:00", "\\a\\b.dll"]))
row = st.dictionaries(st.sampled_from(["PID", "Pid", "PPID", "ImageFileName", "Process", "Name", "CreateTime",
                                       "ExitTime", "Base", "Path", "MappedPath", "InLoad", "InMem", "Protection",
                                       "PrivateMemory", "Hexdump", "Type", "GrantedAccess", "Notes"]), cell, max_size=10)


@settings(max_examples=200, deadline=None)
@given(st.dictionaries(st.sampled_from(["pslist", "psscan", "dlllist", "ldrmodules", "malfind", "handles",
                                        "hollowprocesses"]), st.lists(row, max_size=6)))
def test_analyzer_never_raises(rows):
    a = MemoryAnalyzer()
    for e in a.to_events(a.analyze(rows)):
        e.to_json()
