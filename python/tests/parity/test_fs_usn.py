"""Parity: veritas-fs USN journal records (fs-tool usn) vs dissect.ntfs on plaso UsnJrnl.raw."""
from __future__ import annotations

import functools
import importlib.metadata
import io
import json
import os
import subprocess
from collections import defaultdict
from pathlib import Path

import pytest

usnjrnl = pytest.importorskip("dissect.ntfs.usnjrnl")

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "testdata" / "corpus"
RESULTS = ROOT / "parity" / "results"
pytestmark = pytest.mark.parity


@functools.lru_cache(maxsize=1)
def fs_tool() -> Path:
    subprocess.run(["cargo", "build", "-q", "-p", "veritas-fs", "--bin", "fs-tool"], cwd=ROOT, check=True)
    return ROOT / "target" / "debug" / ("fs-tool.exe" if os.name == "nt" else "fs-tool")


def run_jsonl(*args) -> list[dict]:
    out = subprocess.run([str(fs_tool()), *map(str, args)], cwd=ROOT, check=True, capture_output=True).stdout
    return [json.loads(line) for line in out.decode("utf-8").splitlines() if line.strip()]


class Tally:
    def __init__(self):
        self.fields = defaultdict(lambda: {"agree": 0, "total": 0})
        self.mismatches: list[str] = []

    def add(self, field: str, ours, ref, ctx: str = ""):
        f = self.fields[field]
        f["total"] += 1
        if ours == ref:
            f["agree"] += 1
        elif len(self.mismatches) < 50:
            self.mismatches.append(f"{ctx} {field}: ours={ours!r} ref={ref!r}")


def write_result(name, reference, samples, ours, ref, tally: Tally, notes=""):
    RESULTS.mkdir(parents=True, exist_ok=True)
    doc = {"parser": name, "reference": reference, "samples": samples, "records_ours": ours, "records_reference": ref,
           "fields": {k: tally.fields[k] for k in sorted(tally.fields)}, "notes": notes}
    (RESULTS / f"{name}.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def seg(ref) -> int:
    return (int(ref.SegmentNumberHighPart) << 32) | int(ref.SegmentNumberLowPart)


def test_usn_vs_dissect():
    sample = CORPUS / "plaso" / "UsnJrnl.raw"
    ours = run_jsonl("usn", sample)
    ref = list(usnjrnl.UsnJrnl(io.BytesIO(sample.read_bytes())).records())
    t = Tally()
    t.add("record_count", len(ours), len(ref))
    by_off = {o["offset"]: o for o in ours}
    for r in ref:
        rec = r.record
        o = by_off.get(r.offset)
        t.add("offset", o is not None, True, str(r.offset))
        if o is None:
            continue
        ctx = f"@{r.offset}"
        t.add("usn", o["usn"], int(rec.Usn), ctx)
        t.add("timestamp_raw", o["timestamp_raw"], int(rec.TimeStamp), ctx)
        t.add("timestamp_ns", o["timestamp"], int(r.timestamp_ns) if hasattr(r, "timestamp_ns") else None, ctx)
        t.add("reason_flags", o["reason"], int(rec.Reason), ctx)
        t.add("filename", o["name"], r.filename, ctx)
        t.add("file_reference", (o["file_entry"], o["file_sequence"]), (seg(rec.FileReferenceNumber), int(rec.FileReferenceNumber.SequenceNumber)), ctx)
        t.add("parent_file_reference", (o["parent_entry"], o["parent_sequence"]), (seg(rec.ParentFileReferenceNumber), int(rec.ParentFileReferenceNumber.SequenceNumber)), ctx)
        t.add("file_attributes", o["file_attributes"], int(rec.FileAttributes), ctx)
        t.add("source_info", o["source_info"], int(rec.SourceInfo), ctx)
        t.add("major_version", o["major_version"], int(rec.MajorVersion), ctx)
    write_result("fs_usn", f"dissect.ntfs {importlib.metadata.version('dissect.ntfs')} UsnJrnl", ["plaso/UsnJrnl.raw"], len(ours), len(ref), t,
                 "Raw $J extract (USN_RECORD_V2). V3/V4 decoding is covered by Rust unit tests with hand-built records.")
    bad = {k: v for k, v in t.fields.items() if v["agree"] != v["total"]}
    assert not bad, (bad, t.mismatches)
