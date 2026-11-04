"""Parity: veritas-fs partition tables vs pytsk3 Volume_Info."""
from __future__ import annotations

import functools
import json
import os
import subprocess
from collections import defaultdict
from pathlib import Path

import pytest

pytsk3 = pytest.importorskip("pytsk3")

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


SAMPLES = ["dfvfs/mbr.raw", "dfvfs/gpt.raw", "dfvfs/gpt_in_mbr.raw", "plaso/tsk_volume_system.raw", "dfvfs/apfs_encrypted.dmg"]


def test_partitions_vs_pytsk3():
    t = Tally()
    n_ours = n_ref = 0
    for s in SAMPLES:
        ours = run_jsonl("partitions", CORPUS / s)
        vs = pytsk3.Volume_Info(pytsk3.Img_Info(str(CORPUS / s)))
        ref = [p for p in vs if p.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC]
        n_ours += len(ours)
        n_ref += len(ref)
        t.add("partition_count", len(ours), len(ref), s)
        for o, r in zip(ours, ref):
            t.add("start", o["start_lba"], r.start, s)
            t.add("length", o["num_sectors"], r.len, s)
            t.add("description", o["description"], r.desc.decode("utf-8", "replace"), s)
    write_result("fs_volume", f"pytsk3 {pytsk3.TSK_VERSION_STR} Volume_Info (allocated partitions)", SAMPLES, n_ours, n_ref, t,
                 "MBR descriptions use TSK's '<name> (0xNN)' format; GPT descriptions are the partition name.")
    assert not t.mismatches, t.mismatches
