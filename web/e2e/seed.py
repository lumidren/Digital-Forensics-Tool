"""Seed a case timeline for the web end-to-end tests.

Inserts a small, deterministic intrusion story directly into the timeline store through
``AppContext`` (no parsers involved), so the analytics rules produce lateral-movement,
execution, anti-forensics and file-provenance findings, and the memory view has a process tree.

Usage (same environment variables as the API process)::

    python web/e2e/seed.py --case C-... --evidence-sha256 <sha256> [--filler 2000]

Prints a JSON summary on stdout.
"""
from __future__ import annotations

import argparse
import json
import sys

from veritas.api.config import load
from veritas.api.context import AppContext
from veritas.timeline.schema import Event

NS = 1_000_000_000
BASE = 1_710_406_800 * NS  # 2024-03-14T09:00:00Z
ATTACKER = "10.0.0.66"


def ev(sha: str, offset: int, ts: int | None, data_type: str, desc: str, message: str, *, host: str | None = None,
       user: str | None = None, path: str = "", parser: str = "seed", attrs: dict | None = None) -> Event:
    return Event(
        data_type=data_type, timestamp_desc=desc, message=message, timestamp=ts, source_short="SEED", source_long="E2E seed",
        evidence_sha256=sha, evidence_path=path, offset=offset, parser=parser, parser_version="1.0.0", host=host, user=user,
        attrs=attrs or {},
    )


def evtx(sha: str, offset: int, ts: int, host: str, eid: int, message: str, data: dict, user: str | None = None) -> Event:
    return ev(sha, offset, ts, "windows:evtx:record", "Event Time", message, host=host, user=user,
              path="C:/Windows/System32/winevt/Logs/Security.evtx", parser="evtx",
              attrs={"event_identifier": eid, "channel": "Security" if eid != 7045 else "System",
                     "source_name": "Microsoft-Windows-Security-Auditing" if eid != 7045 else "Service Control Manager",
                     "computer_name": host, "record_number": 1000 + offset, "event_data": data,
                     "xml_string": f"<Event><System><EventID>{eid}</EventID><Computer>{host}</Computer></System></Event>"})


def story(sha: str) -> list[Event]:
    m = 60 * NS
    mimikatz_path = "C:\\Users\\bob\\Downloads\\mimikatz.exe"
    out = [
        ev(sha, 1, BASE + 1 * m, "chrome:history:file_downloaded", "File Downloaded",
           "Downloaded https://evil.example.com/tools/mimikatz.exe to C:\\Users\\bob\\Downloads\\mimikatz.exe",
           host="WS01", user="bob", path="C:/Users/bob/AppData/Local/Google/Chrome/User Data/Default/History", parser="chrome_history",
           attrs={"url": "https://evil.example.com/tools/mimikatz.exe", "full_path": mimikatz_path, "received_bytes": 1250304,
                  "total_bytes": 1250304, "state": "complete", "mime_type": "application/octet-stream"}),
        ev(sha, 2, BASE + 5 * m, "windows:prefetch:execution", "Last Time Executed", "Prefetch: MIMIKATZ.EXE was executed (run count 3)",
           host="WS01", user="bob", path="C:/Windows/Prefetch/MIMIKATZ.EXE-5F1A2B3C.pf", parser="prefetch",
           attrs={"executable": "MIMIKATZ.EXE", "run_count": 3, "prefetch_hash": "5F1A2B3C", "format_version": 30,
                  "run_times": [BASE + 5 * m, BASE + 4 * m, BASE + 3 * m],
                  "mapped_files": ["\\VOLUME{01d9a1b2c3d4e5f6-1234abcd}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                                   "\\VOLUME{01d9a1b2c3d4e5f6-1234abcd}\\USERS\\BOB\\DOWNLOADS\\MIMIKATZ.EXE",
                                   "\\VOLUME{01d9a1b2c3d4e5f6-1234abcd}\\WINDOWS\\SYSTEM32\\SAMLIB.DLL"]}),
        evtx(sha, 3, BASE + 10 * m, "WS01", 4648, "A logon was attempted using explicit credentials (target FS01)",
             {"SubjectUserName": "bob", "TargetUserName": "svc_backup", "TargetServerName": "FS01", "ProcessName": "C:\\Windows\\System32\\cmd.exe"},
             user="bob"),
        evtx(sha, 4, BASE + 11 * m, "FS01", 4624, f"An account was successfully logged on (type 3 from {ATTACKER})",
             {"LogonType": "3", "IpAddress": ATTACKER, "TargetUserName": "svc_backup", "LogonProcessName": "NtLmSsp",
              "AuthenticationPackageName": "NTLM", "WorkstationName": "WS01"}, user="svc_backup"),
        evtx(sha, 5, BASE + 12 * m, "FS01", 7045, "A service was installed in the system: PSEXESVC",
             {"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe", "ServiceType": "user mode service",
              "StartType": "demand start", "AccountName": "LocalSystem"}),
        evtx(sha, 6, BASE + 20 * m, "FS01", 1102, "The audit log was cleared", {"SubjectUserName": "svc_backup", "SubjectDomainName": "CORP"},
             user="svc_backup"),
        ev(sha, 7, BASE + 25 * m, "fs:ntfs:usn_change", "Content Modification Time", "USN: mimikatz.exe FILE_DELETE|CLOSE",
           host="WS01", path="C:/$Extend/$UsnJrnl:$J", parser="usnjrnl",
           attrs={"path": mimikatz_path, "filename": "mimikatz.exe", "usn": 88213504, "file_reference": 120334,
                  "parent_file_reference": 98211, "update_reason_flags": "FILE_DELETE|CLOSE"}),
        ev(sha, 8, BASE - 30 * 86400 * NS, "fs:stat:ntfs", "Content Modification Time", "C:\\Users\\bob\\AppData\\Roaming\\updater.exe ($SI)",
           host="WS01", path="C:/$MFT", parser="mft",
           attrs={"path": "C:\\Users\\bob\\AppData\\Roaming\\updater.exe", "mft_entry": 120400, "size": 48128,
                  "si_crtime_ns": BASE - 30 * 86400 * NS, "si_mtime_ns": BASE - 30 * 86400 * NS,
                  "fn_crtime_ns": BASE + 2 * m + 123456789, "fn_mtime_ns": BASE + 2 * m + 123456789}),
    ]
    # Memory image of WS01: process list with an injected and a hidden process.
    procs = [(4, 0, "System"), (612, 4, "smss.exe"), (700, 612, "wininit.exe"), (812, 700, "lsass.exe"),
             (2120, 700, "explorer.exe"), (4242, 2120, "mimikatz.exe"), (5100, 2120, "rundll32.exe")]
    off = 100
    for pid, ppid, name in procs:
        for plugin in ("windows.pslist.PsList", "windows.psscan.PsScan"):
            off += 1
            out.append(ev(sha, off, BASE + 6 * m + pid, "memory:process", "Creation Time",
                          f"[{plugin.split('.')[1]}] ImageFileName={name} PID={pid} PPID={ppid}", host="WS01", path="memory.raw",
                          parser="volatility3", attrs={"plugin": plugin, "PID": pid, "PPID": ppid, "ImageFileName": name,
                                                       "CreateTime": "2024-03-14T09:06:00+00:00"}))
    off += 1
    out.append(ev(sha, off, BASE + 6 * m + 6666, "memory:process", "Creation Time", "[psscan] ImageFileName=svch0st.exe PID=6666 PPID=2120",
                  host="WS01", path="memory.raw", parser="volatility3",
                  attrs={"plugin": "windows.psscan.PsScan", "PID": 6666, "PPID": 2120, "ImageFileName": "svch0st.exe"}))
    off += 1
    out.append(ev(sha, off, None, "memory:injection", "Not a time", "[malfind] Process=rundll32.exe PID=5100 Protection=PAGE_EXECUTE_READWRITE",
                  host="WS01", path="memory.raw", parser="volatility3",
                  attrs={"plugin": "windows.malfind.Malfind", "PID": 5100, "Process": "rundll32.exe", "Start VPN": 0x1F0000,
                         "End VPN": 0x1FFFFF, "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "4d 5a 90 00 03 00 00 00  MZ......"}))
    off += 1
    out.append(ev(sha, off, None, "memory:network:connection", "Not a time", f"[netscan] TCPv4 192.168.1.20:49812 -> {ATTACKER}:443 ESTABLISHED",
                  host="WS01", path="memory.raw", parser="volatility3",
                  attrs={"plugin": "windows.netscan.NetScan", "PID": 4242, "Proto": "TCPv4", "LocalAddr": "192.168.1.20", "LocalPort": 49812,
                         "ForeignAddr": ATTACKER, "ForeignPort": 443, "State": "ESTABLISHED", "Owner": "mimikatz.exe"}))
    return out


def filler(sha: str, n: int) -> list[Event]:
    out = []
    hosts = ["WS01", "WS02", "FS01", "DC01"]
    for i in range(n):
        ts = BASE - 3 * 86400 * NS + i * 97 * NS
        out.append(ev(sha, 10_000 + i, ts, "windows:evtx:record", "Event Time", f"Background activity record {i}",
                      host=hosts[i % len(hosts)], user="system", path="C:/Windows/System32/winevt/Logs/System.evtx", parser="evtx",
                      attrs={"event_identifier": 7036, "channel": "System", "source_name": "Service Control Manager",
                             "record_number": 50_000 + i, "event_data": {"param1": "Windows Update", "param2": "running"}}))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--case", required=True)
    ap.add_argument("--evidence-sha256", required=True)
    ap.add_argument("--filler", type=int, default=2000)
    args = ap.parse_args(argv)
    ctx = AppContext(load())
    events = story(args.evidence_sha256) + filler(args.evidence_sha256, args.filler)
    n = ctx.timeline.ingest(args.case, events)
    print(json.dumps({"case": args.case, "ingested": n, "total": ctx.timeline.count(args.case)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
