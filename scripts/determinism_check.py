#!/usr/bin/env python3
"""Determinism check: same evidence -> identical parsed output and identical hashes.

Runs every parser over every corpus sample twice (fresh processes, different PYTHONHASHSEED and
working directories) and writes ``determinism/<os>.json`` mapping sample -> SHA-256 of the sorted
JSONL output. ``--compare a.json b.json`` checks that two runs, possibly from different machines
or operating systems, produced identical digests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "testdata" / "corpus"

# (parser, sample relative to corpus). Parsers resolve through veritas.pipeline.runner.
SAMPLES = [
    ("evtx", "plaso/evtx/System.evtx"),
    ("prefetch", "plaso/winprefetch/CMD.EXE-087B4001.pf"),
    ("prefetch", "plaso/winprefetch/WUAUCLT.EXE-830BCC14.pf"),
    ("lnk", "plaso/NeroInfoTool.lnk"),
    ("jumplist", "plaso/automaticDestinations-ms/1b4dd67f29cb1962.automaticDestinations-ms"),
    ("regf-events", "plaso/NTUSER.DAT"),
    ("regf-events", "plaso/SYSTEM"),
    ("journald", "plaso/systemd/journal/system.journal"),
    ("plist", "plaso/plist/InstallHistory.plist"),
    ("mft", "plaso/MFT"),
    ("usn", "plaso/UsnJrnl.raw"),
    ("fs-events", "dfvfs/ntfs.raw"),
    ("fs-events", "dfvfs/ext4.raw"),
    ("fs-events", "dfvfs/fat12.raw"),
    ("fs-events", "dfvfs/apfs.raw"),
    ("auto", "plaso/chrome/History"),
    ("auto", "plaso/firefox/places.sqlite"),
    ("auto", "plaso/syslog/syslog"),
    ("auto", "plaso/bash_history"),
    ("pcap", "plaso/test.pcap"),
    ("pe", "plaso/test_pe.exe"),
]


def run_once(parser: str, sample: pathlib.Path, seed: str) -> tuple[bool, str, int]:
    env = {**os.environ, "PYTHONHASHSEED": seed, "TZ": "UTC"}
    with tempfile.TemporaryDirectory() as wd:
        proc = subprocess.run([sys.executable, "-m", "veritas.pipeline.runner", parser, str(sample), "0" * 64, sample.relative_to(CORPUS).as_posix()],
                              capture_output=True, cwd=wd, env=env)
    if proc.returncode != 0:
        return False, proc.stderr.decode("utf-8", "replace")[-300:], 0
    lines = [l for l in proc.stdout.splitlines() if l.strip()]
    return True, hashlib.sha256(b"\n".join(lines)).hexdigest(), len(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "determinism" / f"{platform.system().lower()}.json"))
    ap.add_argument("--compare", nargs=2)
    args = ap.parse_args()
    if args.compare:
        a, b = (json.loads(pathlib.Path(p).read_text(encoding="utf-8")) for p in args.compare)
        diffs = [k for k in sorted(set(a["digests"]) | set(b["digests"])) if a["digests"].get(k) != b["digests"].get(k)]
        for k in diffs:
            print("DIFFERENT", k, a["digests"].get(k), b["digests"].get(k))
        print(f"compared {len(a['digests'])} samples across {a['platform']} and {b['platform']}: {len(diffs)} differences")
        return 1 if diffs else 0
    digests, failures, skipped = {}, [], []
    for parser, rel in SAMPLES:
        sample = CORPUS / rel
        if not sample.exists():
            skipped.append(rel)
            continue
        ok1, d1, n1 = run_once(parser, sample, "1")
        ok2, d2, n2 = run_once(parser, sample, "987654")
        key = f"{parser}:{rel}"
        if not (ok1 and ok2):
            failures.append(f"{key}: parser failed: {d1 if not ok1 else d2}")
            continue
        if d1 != d2:
            failures.append(f"{key}: two runs differ ({d1} vs {d2})")
        digests[key] = d1
        print(f"{'OK ' if d1 == d2 else 'BAD'} {key} events={n1} sha256={d1[:16]}")
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"platform": f"{platform.system()} {platform.machine()} py{platform.python_version()}", "digests": digests, "failures": failures, "skipped": skipped}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    for f in failures:
        print("FAIL", f)
    print(f"determinism: {len(digests)} samples stable, {len(failures)} failures, {len(skipped)} skipped")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
