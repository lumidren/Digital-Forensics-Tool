"""Parity: veritas-fs Volume Shadow Copy stores (fs-tool vss) vs pyvshadow on dfvfs vss.raw."""
from __future__ import annotations

import functools
import hashlib
import json
import os
import subprocess
from collections import defaultdict
from pathlib import Path

import pytest

pyvshadow = pytest.importorskip("pyvshadow")

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


def test_vss_vs_pyvshadow():
    sample = CORPUS / "dfvfs" / "vss.raw"
    ours = run_jsonl("vss", sample)
    f = open(sample, "rb")
    v = pyvshadow.volume()
    v.open_file_object(f)
    t = Tally()
    t.add("store_count", len(ours), v.number_of_stores)
    for i in range(v.number_of_stores):
        s = v.get_store(i)
        o = ours[i] if i < len(ours) else {}
        ctx = f"store{i}"
        t.add("identifier", o.get("identifier"), s.identifier, ctx)
        t.add("copy_identifier", o.get("copy_identifier"), s.copy_identifier, ctx)
        t.add("copy_set_identifier", o.get("copy_set_identifier"), s.copy_set_identifier, ctx)
        t.add("creation_time", o.get("creation_time_raw"), s.get_creation_time_as_integer(), ctx)
        t.add("volume_size", o.get("volume_size"), s.volume_size, ctx)
        t.add("store_size", o.get("volume_size"), s.size, ctx)
        t.add("block_descriptor_count", o.get("descriptor_count"), s.number_of_blocks, ctx)
        first = s.read_buffer_at_offset(1 << 20, 0)
        t.add("first_mib_sha256", o.get("first_mib_sha256"), hashlib.sha256(first).hexdigest(), ctx)
    v.close()
    f.close()
    write_result("fs_vss", f"pyvshadow {pyvshadow.get_version()}", ["dfvfs/vss.raw"], len(ours), len(ours), t,
                 "Full-store SHA-256 of both stores also matches pyvshadow (Rust test vss_store_data_matches_pyvshadow). "
                 "store_size compares the shadow-copy size (pyvshadow store.size), i.e. the volume size.")
    bad = {k: v for k, v in t.fields.items() if v["agree"] != v["total"]}
    assert not bad, (bad, t.mismatches)
