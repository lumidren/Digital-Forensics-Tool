"""Parity: veritas-fs NTFS (fs-tool mft) vs pyfsntfs and pytsk3 on dfvfs ntfs.raw / vss.raw and plaso MFT."""
from __future__ import annotations

import functools
import json
import os
import subprocess
from collections import defaultdict
from pathlib import Path

import pytest

pyfsntfs = pytest.importorskip("pyfsntfs")
pytsk3 = pytest.importorskip("pytsk3")

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "testdata" / "corpus"
RESULTS = ROOT / "parity" / "results"
pytestmark = pytest.mark.parity
EPOCH_DIFF = 116444736000000000


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


def best_fn(attrs: list[dict]) -> dict | None:
    rank = {1: 0, 3: 0, 0: 1, 2: 2}
    return min(attrs, key=lambda a: rank.get(a["namespace"], 3)) if attrs else None


def ref_entry(e) -> dict:
    """Fields of one pyfsntfs file entry (FN attributes read directly)."""
    fns, si, data_attr_size = [], None, None
    for k in range(e.number_of_attributes):
        a = e.get_attribute(k)
        if a.attribute_type == 0x80 and not a.attribute_name and data_attr_size is None:
            data_attr_size = a.data_size
        if a.attribute_type == 0x30:
            fns.append({"name": a.name, "namespace": a.name_space, "parent": a.parent_file_reference & 0xFFFFFFFFFFFF,
                        "times": (a.get_creation_time_as_integer(), a.get_modification_time_as_integer(),
                                  a.get_access_time_as_integer(), a.get_entry_modification_time_as_integer())})
        elif a.attribute_type == 0x10 and si is None:
            si = (a.get_creation_time_as_integer(), a.get_modification_time_as_integer(), a.get_access_time_as_integer(),
                  a.get_entry_modification_time_as_integer())
    try:
        ads = sorted(e.get_alternate_data_stream(j).name for j in range(e.number_of_alternate_data_streams))
    except OSError:
        ads = None  # pyfsntfs cannot build streams whose run list disagrees with the allocated size
    return {"fns": fns, "si": si, "ads": ads, "size": e.size, "data_attr_size": data_attr_size or 0, "alloc": e.is_allocated()}


def compare_pyfsntfs(t: Tally, ours: list[dict], count: int, get, label: str, size_from_attr: bool = False) -> tuple[int, int]:
    by = {o["entry"]: o for o in ours}
    nref = 0
    for i in range(count):
        try:
            e = get(i)
            r = ref_entry(e)
            r_alloc = r["alloc"]
        except OSError:
            continue  # pyfsntfs rejects records without a FILE header; so do we
        nref += 1
        o = by.get(i)
        t.add("mft_entry", o is not None, True, f"{label}#{i}")
        if o is None:
            continue
        t.add("is_allocated", o["in_use"], r_alloc, f"{label}#{i}")
        t.add("size", sum(s["size"] for s in o["streams"] if s["name"] == ""), r["data_attr_size"] if size_from_attr else r["size"], f"{label}#{i}")
        osi = o["si"]
        for idx, f in enumerate(("si_crtime", "si_mtime", "si_atime", "si_ctime")):
            ov = None if osi is None else [osi["crtime"], osi["mtime"], osi["atime"], osi["ctime"]][idx]
            rv = None if r["si"] is None else r["si"][idx]
            t.add(f, ov, rv, f"{label}#{i}")
        ofn = best_fn(o["file_names"])
        rfn = best_fn(r["fns"])
        t.add("name", ofn and ofn["name"], rfn and rfn["name"], f"{label}#{i}")
        t.add("parent_entry", ofn and ofn["parent_entry"], rfn and rfn["parent"], f"{label}#{i}")
        t.add("fn_count", len(o["file_names"]), len(r["fns"]), f"{label}#{i}")
        for idx, f in enumerate(("fn_crtime", "fn_mtime", "fn_atime", "fn_ctime")):
            ov = None if ofn is None else [ofn["crtime"], ofn["mtime"], ofn["atime"], ofn["ctime"]][idx]
            rv = None if rfn is None else rfn["times"][idx]
            t.add(f, ov, rv, f"{label}#{i}")
        if r["ads"] is not None:
            t.add("ads_names", sorted(s["name"] for s in o["streams"] if s["name"]), r["ads"], f"{label}#{i}")
    return len(ours), nref


def test_ntfs_vs_pyfsntfs():
    t = Tally()
    n_ours = n_ref = 0
    for s in ("dfvfs/ntfs.raw", "dfvfs/vss.raw"):
        ours = run_jsonl("mft", CORPUS / s)
        f = open(CORPUS / s, "rb")
        v = pyfsntfs.volume()
        v.open_file_object(f)
        a, b = compare_pyfsntfs(t, ours, v.number_of_file_entries, v.get_file_entry, s)
        n_ours, n_ref = n_ours + a, n_ref + b
        v.close()
        f.close()
    ours = run_jsonl("mft", CORPUS / "plaso/MFT")
    f = open(CORPUS / "plaso/MFT", "rb")
    m = pyfsntfs.mft_metadata_file()
    m.open_file_object(f)
    a, b = compare_pyfsntfs(t, ours, m.number_of_file_entries, m.get_file_entry, "plaso/MFT", size_from_attr=True)
    n_ours, n_ref = n_ours + a, n_ref + b
    m.close()
    f.close()
    write_result("fs_ntfs", f"pyfsntfs {pyfsntfs.get_version()}", ["dfvfs/ntfs.raw", "dfvfs/vss.raw", "plaso/MFT"], n_ours, n_ref, t,
                 "Records pyfsntfs refuses (no FILE header) are excluded from totals. For the bare plaso $MFT extract "
                 "pyfsntfs.mft_metadata_file reports size 0 for non-resident data, so size is compared with the unnamed "
                 "$DATA attribute data_size read through pyfsntfs. ads_names skipped where pyfsntfs raises on "
                 "inconsistent run lists (6 deleted records).")
    bad = {k: v for k, v in t.fields.items() if v["agree"] != v["total"]}
    assert not bad, (bad, t.mismatches)


def walk_tsk(d, path, out, depth=0):
    for f in d:
        n = f.info.name.name.decode("utf-8", "replace")
        if n in (".", "..") or f.info.meta is None or n == "$OrphanFiles":
            continue
        p = f"{path}/{n}"
        out.append((p, f))
        if f.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR and depth < 16:
            try:
                walk_tsk(f.as_directory(), p, out, depth + 1)
            except OSError:
                pass


def tsk_ns(sec, nano):
    return sec * 1_000_000_000 + nano if sec else None


def ft_ns(ft):
    return (ft - EPOCH_DIFF) * 100 if ft else None


def test_ntfs_vs_pytsk3():
    t = Tally()
    n_ours = n_ref = 0
    for s in ("dfvfs/ntfs.raw", "dfvfs/vss.raw"):
        ours = {o["path"]: o for o in run_jsonl("mft", CORPUS / s) if o.get("path")}
        fs = pytsk3.FS_Info(pytsk3.Img_Info(str(CORPUS / s)))
        items: list = []
        walk_tsk(fs.open_dir("/"), "", items)
        n_ours += len(ours)
        n_ref += len(items)
        for p, f in items:
            m = f.info.meta
            o = ours.get(p)
            t.add("name_path", o is not None, True, f"{s}:{p}")
            if o is None:
                continue
            t.add("mft_entry", o["entry"], m.addr, p)
            t.add("parent_entry", best_fn(o["file_names"])["parent_entry"], f.info.name.par_addr, p)
            t.add("is_allocated", o["in_use"], bool(m.flags & pytsk3.TSK_FS_META_FLAG_ALLOC), p)
            if f.info.name.type != pytsk3.TSK_FS_NAME_TYPE_DIR:
                t.add("size", sum(x["size"] for x in o["streams"] if x["name"] == ""), m.size, p)
            si = o["si"]
            t.add("si_crtime", ft_ns(si["crtime"]), tsk_ns(m.crtime, m.crtime_nano), p)
            t.add("si_mtime", ft_ns(si["mtime"]), tsk_ns(m.mtime, m.mtime_nano), p)
            t.add("si_atime", ft_ns(si["atime"]), tsk_ns(m.atime, m.atime_nano), p)
            t.add("si_ctime", ft_ns(si["ctime"]), tsk_ns(m.ctime, m.ctime_nano), p)
            ads = sorted(a.info.name.decode("utf-8", "replace") for a in f if a.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA and a.info.name)
            t.add("ads_names", sorted(x["name"] for x in o["streams"] if x["name"]), ads, p)
    write_result("fs_ntfs_tsk", f"pytsk3 {pytsk3.TSK_VERSION_STR}", ["dfvfs/ntfs.raw", "dfvfs/vss.raw"], n_ours, n_ref, t,
                 "Directory sizes not compared (TSK reports $I30 allocation size). TSK times are $STANDARD_INFORMATION.")
    bad = {k: v for k, v in t.fields.items() if v["agree"] != v["total"]}
    assert not bad, (bad, t.mismatches)
