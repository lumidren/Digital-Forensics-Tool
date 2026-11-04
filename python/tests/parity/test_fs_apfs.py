"""Parity: veritas-fs APFS (fs-tool ls -r / info) vs pyfsapfs on dfvfs apfs.raw."""
from __future__ import annotations

import functools
import json
import os
import subprocess
from collections import defaultdict
from pathlib import Path

import pytest

pyfsapfs = pytest.importorskip("pyfsapfs")

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


def walk(d, prefix, out, depth=0):
    for i in range(d.number_of_sub_file_entries):
        s = d.get_sub_file_entry(i)
        p = f"{prefix}/{s.name}"
        out.append((p, s))
        if (s.file_mode & 0o170000) == 0o040000 and depth < 64:
            walk(s, p, out, depth + 1)


def test_apfs_vs_pyfsapfs():
    sample = CORPUS / "dfvfs" / "apfs.raw"
    ours = {o["path"]: o for o in run_jsonl("ls", sample, "-r")}
    info = run_jsonl("info", sample)[0]
    f = open(sample, "rb")
    c = pyfsapfs.container()
    c.open_file_object(f)
    t = Tally()
    t.add("container_identifier", info["container"]["uuid"], c.identifier)
    t.add("volume_count", len(info["volumes"]), c.number_of_volumes)
    items: list = []
    for vi in range(c.number_of_volumes):
        v = c.get_volume(vi)
        ov = info["volumes"][vi]
        t.add("volume_name", ov["name"], v.name)
        t.add("volume_identifier", ov["uuid"], v.identifier)
        # pyfsapfs exposes no snapshot API: cross-check our enumeration against the volume superblock count.
        t.add("snapshot_count", len(ov["snapshots"]), ov["num_snapshots"])
        walk(v.get_root_directory(), "", items)
    for p, s in items:
        o = ours.get(p)
        t.add("name_path", o is not None, True, p)
        if o is None:
            continue
        t.add("identifier", o["id"], s.identifier, p)
        t.add("parent_identifier", o["parent_id"], s.parent_identifier, p)
        t.add("size", o["size"], s.size, p)
        t.add("mode", o["mode"], s.file_mode, p)
        t.add("uid", o["uid"], s.owner_identifier, p)
        t.add("gid", o["gid"], s.group_identifier, p)
        t.add("nlink", o["nlink"], s.number_of_links, p)
        t.add("crtime", o["crtime"], s.get_creation_time_as_integer(), p)
        t.add("mtime", o["mtime"], s.get_modification_time_as_integer(), p)
        t.add("atime", o["atime"], s.get_access_time_as_integer(), p)
        t.add("ctime", o["ctime"], s.get_inode_change_time_as_integer(), p)
        t.add("added_time", o["added"], s.get_added_time_as_integer(), p)
        t.add("xattr_names", o["xattrs"], sorted(s.get_extended_attribute(j).name for j in range(s.number_of_extended_attributes)), p)
        if (s.file_mode & 0o170000) == 0o120000:
            t.add("symlink_target", o["symlink_target"], s.symbolic_link_target, p)
    c.close()
    f.close()
    write_result("fs_apfs", f"pyfsapfs {pyfsapfs.get_version()}", ["dfvfs/apfs.raw"], len(ours), len(items), t,
                 "pyfsapfs has no snapshot API; snapshot_count compares our snap_metadata enumeration with the APSB "
                 "num_snapshots field (0 on the corpus). Encrypted volumes: see python/tests/unit/test_decrypt.py.")
    bad = {k: v for k, v in t.fields.items() if v["agree"] != v["total"]}
    assert not bad, (bad, t.mismatches)
