#!/usr/bin/env python3
"""Measure pipeline throughput and write docs/BENCHMARKS.md.

Stages measured on this machine:
  1. Acquisition-side hashing (MD5+SHA-256+SHA3-256, one pass) and E01 imaging of a synthetic disk
     (half zero blocks, half random blocks: compressible like a real partially-used disk).
  2. Parser throughput on reference-corpus artifacts (veritas bench).
  3. Timeline ingest rate and search latency (p50/p95/p99) at N events in the SQLite FTS5 store.

A 500 GB end-to-end run is not possible on a developer laptop with ~55 GB free; the 500 GB figure
in the report is a model built from these per-stage measurements and is labelled as such.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
BIN = ROOT / "target" / "release"
EXE = ".exe" if os.name == "nt" else ""
sys.path.insert(0, str(ROOT / "python"))


def make_disk(path: pathlib.Path, gib: int) -> None:
    rnd = random.Random(1234)
    block = 4 << 20
    zero = bytes(block)
    with open(path, "wb") as fh:
        for i in range(gib * 256):
            fh.write(zero if i % 2 == 0 else rnd.randbytes(block))


def timed(cmd: list[str]) -> float:
    t = time.perf_counter()
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return time.perf_counter() - t


def gbh(nbytes: int, secs: float) -> float:
    return nbytes / 1e9 / secs * 3600


def bench_acquisition(work: pathlib.Path, gib: int) -> list[dict]:
    disk = work / "disk.raw"
    make_disk(disk, gib)
    size = disk.stat().st_size
    rows = []
    t = timed([str(BIN / f"veritas{EXE}"), "hash", str(disk)])
    rows.append({"stage": "hash (MD5+SHA-256+SHA3-256, single pass)", "bytes": size, "seconds": round(t, 2), "gb_per_hour": round(gbh(size, t))})
    for level in ("fast", "best"):
        out = work / f"img_{level}"
        args = [str(BIN / f"ewf-tool{EXE}"), "write", str(disk), str(out)]
        help_text = subprocess.run([str(BIN / f"ewf-tool{EXE}"), "write", "--help"], capture_output=True, text=True).stdout
        if "--compression" in help_text:
            args += ["--compression", level]
        t = timed(args)
        e01 = sum(p.stat().st_size for p in work.glob(f"img_{level}.E*"))
        rows.append({"stage": f"E01 imaging (zlib {level}) + hashing", "bytes": size, "seconds": round(t, 2), "gb_per_hour": round(gbh(size, t)), "output_bytes": e01})
        t = timed([str(BIN / f"ewf-tool{EXE}"), "verify", str(work / f"img_{level}.E01")])
        rows.append({"stage": f"E01 verify (decompress + re-hash, {level})", "bytes": size, "seconds": round(t, 2), "gb_per_hour": round(gbh(size, t))})
        for p in work.glob(f"img_{level}.E*"):
            p.unlink()
        if "--compression" not in help_text:
            break
    disk.unlink()
    return rows


def bench_parsers() -> list[dict]:
    c = ROOT / "testdata" / "corpus"
    inputs = [c / "plaso/evtx/System.evtx", c / "plaso/MFT", c / "plaso/SYSTEM", c / "plaso/SOFTWARE", c / "plaso/NTUSER.DAT", c / "dfvfs/ntfs.raw", c / "dfvfs/ext4.raw", c / "plaso/winprefetch/CMD.EXE-087B4001.pf"]
    inputs = [str(p) for p in inputs if p.exists()]
    out = subprocess.run([str(BIN / f"veritas{EXE}"), "bench", "--repeat", "3", "--json", *inputs], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def bench_timeline(work: pathlib.Path, n: int) -> dict:
    from veritas.timeline.schema import Desc, Event
    from veritas.timeline.store import Query, SqliteTimelineStore

    store = SqliteTimelineStore(work / "timeline.db")
    rnd = random.Random(7)
    words = ["logon", "service", "powershell", "mimikatz", "rdp", "explorer", "svchost", "download", "usb", "registry", "prefetch", "chrome"]
    hosts = [f"WS{i:03d}" for i in range(50)]
    types = ["windows:evtx:record", "fs:stat:ntfs", "windows:registry:key_value", "windows:prefetch:execution", "chrome:history:page_visited"]
    base = 1_600_000_000_000_000_000

    def gen(start: int, count: int):
        for i in range(start, start + count):
            yield Event(data_type=types[i % len(types)], timestamp_desc=Desc.EVENT, message=f"{rnd.choice(words)} {rnd.choice(words)} event {i}",
                        timestamp=base + i * 37_000_000_000, evidence_sha256=f"{i % 20:064x}", evidence_path=f"C:/Windows/file{i % 5000}.log",
                        offset=i, parser="bench", parser_version="1", host=hosts[i % len(hosts)], attrs={"event_identifier": 4624 + i % 50, "user": f"u{i % 300}"})

    t = time.perf_counter()
    batch = 250_000
    for s in range(0, n, batch):
        store.ingest("BENCH", gen(s, min(batch, n - s)))
    ingest_s = time.perf_counter() - t
    span = n * 37_000_000_000
    queries = []
    for i in range(60):
        start = base + rnd.randrange(0, max(1, span - 86400 * 10**9))
        queries.append(Query(text=rnd.choice(words), start_ns=start, end_ns=start + 7 * 86400 * 10**9, limit=200))
        queries.append(Query(text=f"{rnd.choice(words)} {rnd.choice(words)}", limit=200))
        queries.append(Query(data_types=[rnd.choice(types)], hosts=[rnd.choice(hosts)], start_ns=start, end_ns=start + 86400 * 10**9 * 30, limit=200))
        queries.append(Query(attr_equals={"event_identifier": str(4624 + i % 50)}, start_ns=start, end_ns=start + 86400 * 10**9 * 3, limit=200))
    lat = []
    for q in queries:
        t = time.perf_counter()
        store.search("BENCH", q)
        lat.append((time.perf_counter() - t) * 1000)
    lat.sort()
    t = time.perf_counter()
    store.histogram("BENCH", Query(), 86400 * 10**9)
    hist_ms = (time.perf_counter() - t) * 1000
    db_bytes = sum(p.stat().st_size for p in work.glob("timeline.db*"))
    return {"events": n, "ingest_seconds": round(ingest_s, 1), "events_per_second": round(n / ingest_s), "db_bytes": db_bytes, "queries": len(lat),
            "p50_ms": round(statistics.median(lat), 1), "p95_ms": round(lat[int(len(lat) * 0.95) - 1], 1), "p99_ms": round(lat[int(len(lat) * 0.99) - 1], 1),
            "max_ms": round(lat[-1], 1), "full_histogram_ms": round(hist_ms, 1)}


def render(env: dict, acq: list[dict], parsers: list[dict], tl: dict) -> str:
    hash_gbh = next(r["gb_per_hour"] for r in acq if r["stage"].startswith("hash"))
    img_gbh = next(r["gb_per_hour"] for r in acq if r["stage"].startswith("E01 imaging"))
    ver_gbh = next(r["gb_per_hour"] for r in acq if r["stage"].startswith("E01 verify"))
    mft = next((p for p in parsers if p["operation"] == "parse mft"), None)
    mft_rate = (mft["events"] / mft["median_seconds"]) if mft else 0
    lines = [
        "# Benchmarks", "",
        f"Measured {env['date']} on {env['cpu']}, {env['ram_gb']} GB RAM, NVMe SSD, {env['os']}. Release builds, single process unless noted.",
        "Reproduce with `python scripts/benchmark.py`. A fuzzing job was running on one core during part of the run.", "",
        "## 1. Acquisition and integrity", "",
        f"Synthetic {acq[0]['bytes'] / 2**30:.0f} GiB disk: alternating 4 MiB zero and random blocks.", "",
        "| Stage | Seconds | GB/h | Output |", "|---|---|---|---|",
    ]
    for r in acq:
        lines.append(f"| {r['stage']} | {r['seconds']} | {r['gb_per_hour']:,} | {r.get('output_bytes', '') and f'{r['output_bytes'] / 2**30:.2f} GiB'} |")
    lines += ["", "## 2. Parser throughput (reference corpus, median of 3)", "", "| Input | Size | Operation | MB/s | Events |", "|---|---|---|---|---|"]
    for p in parsers:
        lines.append(f"| {p['input']} | {p['bytes']:,} | {p['operation']} | {p['mb_per_s']:.1f} | {p['events'] if p['events'] is not None else ''} |")
    lines += [
        "", "Parser throughput on small samples is dominated by process start-up; MB/s understates sustained rates.",
        f"The most relevant figure for large disks is MFT parsing: {mft_rate:,.0f} file-system events per second." if mft else "",
        "", "## 3. Timeline store (SQLite + FTS5, native profile)", "",
        "| Events | Ingest | Events/s | DB size | Queries | p50 | p95 | p99 | max | Full-range daily histogram |", "|---|---|---|---|---|---|---|---|---|---|",
        f"| {tl['events']:,} | {tl['ingest_seconds']} s | {tl['events_per_second']:,} | {tl['db_bytes'] / 2**30:.1f} GiB | {tl['queries']} | {tl['p50_ms']} ms | {tl['p95_ms']} ms | {tl['p99_ms']} ms | {tl['max_ms']} ms | {tl['full_histogram_ms']} ms |",
        "", "Query mix: single-term full-text within a 7-day window, two-term full-text over all time, data type + host within 30 days, attribute equality within 3 days; limit 200, with exact total counts.",
        "Tens of millions of events per case are served by the ClickHouse backend in the cluster profile; the SQLite store is the single-workstation default.",
        "", "## 4. 500 GB image: processing model", "",
        "Not measured end to end on this machine (about 55 GB free). Processing time for a disk image is the sum of:", "",
        f"* **Integrity re-verification** of the stored object: sequential read and triple hash, measured {hash_gbh:,} GB/h, so 500 GB takes about {500 / hash_gbh * 60:.0f} min.",
        f"* **Acquisition to E01** (agent side, before upload): measured {img_gbh:,} GB/h, about {500 / img_gbh * 60:.0f} min; E01 verification {ver_gbh:,} GB/h.",
        "* **File-system timeline and harvest** scale with metadata, not with image size: a 500 GB Windows system volume typically has 0.5 to 2 million MFT records (8 to 16 events each).",
        f"  At the measured {mft_rate:,.0f} events/s that is roughly {2e6 * 12 / max(mft_rate, 1) / 60:.0f} min for 2 million records." if mft else "",
        f"* **Timeline ingest** of about 30 million events at {tl['events_per_second']:,} events/s: about {30e6 / tl['events_per_second'] / 60:.0f} min (SQLite); ClickHouse ingests in parallel batches.",
        "* **Artifact parsing** (registry, EVTX, prefetch, browser databases) is bounded by the number of harvested artifacts, typically a few GB in total, and runs in parallel worker processes.", "",
        f"Estimated wall-clock for a 500 GB image on one worker: **about {(500 / hash_gbh * 60 + (2e6 * 12 / max(mft_rate, 1) / 60 if mft else 0) + 30e6 / tl['events_per_second'] / 60):.0f} minutes plus artifact parsing**, with no manual steps: verify, fs_timeline, harvest and analytics are DAG steps that resume after interruption (leased job claims). Workers scale horizontally in the cluster profile.",
        "",
    ]
    return "\n".join(l for l in lines if l is not None) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--disk-gib", type=int, default=8)
    ap.add_argument("--events", type=int, default=5_000_000)
    ap.add_argument("--json", default=str(ROOT / "docs" / "benchmarks.json"))
    args = ap.parse_args()
    import datetime

    env = {"date": datetime.date.today().isoformat(), "os": f"{platform.system()} {platform.release()}", "cpu": platform.processor() or platform.machine(), "ram_gb": "?"}
    if os.name == "nt":
        try:
            env["cpu"] = subprocess.run(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor).Name"], capture_output=True, text=True).stdout.strip() or env["cpu"]
            env["ram_gb"] = round(int(subprocess.run(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"], capture_output=True, text=True).stdout.strip()) / 2**30)
        except (ValueError, OSError):
            pass
    work = pathlib.Path(tempfile.mkdtemp(prefix="veritas-bench-"))
    try:
        acq = bench_acquisition(work, args.disk_gib)
        print(json.dumps(acq, indent=1))
        parsers = bench_parsers()
        print(json.dumps(parsers, indent=1))
        tl = bench_timeline(work, args.events)
        print(json.dumps(tl, indent=1))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    pathlib.Path(args.json).write_text(json.dumps({"env": env, "acquisition": acq, "parsers": parsers, "timeline": tl}, indent=1) + "\n", encoding="utf-8")
    (ROOT / "docs" / "BENCHMARKS.md").write_text(render(env, acq, parsers, tl), encoding="utf-8")
    print("wrote docs/BENCHMARKS.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
