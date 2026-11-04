"""Parity: veritas-fs FAT (fs-tool ls -r) vs pyfsfat and pytsk3 on dfvfs fat12.raw and the decrypted
BitLocker To Go volume (FAT16) of dfvfs bdetogo.raw."""
from __future__ import annotations

import calendar
import datetime as dt
import functools
import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

import pytest

pyfsfat = pytest.importorskip("pyfsfat")
pytsk3 = pytest.importorskip("pytsk3")

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "testdata" / "corpus"
RESULTS = ROOT / "parity" / "results"
pytestmark = pytest.mark.parity
TSK_VIRTUAL = {"$MBR", "$FAT1", "$FAT2", "$OrphanFiles"}


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


@pytest.fixture(scope="module")
def images(tmp_path_factory):
    sys.path.insert(0, str(ROOT / "python"))
    from veritas.parsers import decrypt

    out = tmp_path_factory.mktemp("bde") / "bdetogo.dec.raw"
    decrypt.decrypt_bitlocker(str(CORPUS / "dfvfs/bdetogo.raw"), str(out), password="bde-TEST")
    return [("dfvfs/fat12.raw", CORPUS / "dfvfs/fat12.raw"), ("dfvfs/bdetogo.raw (decrypted)", out)]


def dt_ns(d: dt.datetime | None) -> int | None:
    if d is None:
        return None
    return calendar.timegm(d.timetuple()) * 1_000_000_000 + d.microsecond * 1000


def add_month(ns: int | None) -> int | None:
    """pyfsfat 20260826 reports FAT dates one calendar month late (raw entry month 4 -> datetime month 5);
    shift our value the same way to compare everything else exactly."""
    if ns is None:
        return None
    d = dt.datetime(1970, 1, 1) + dt.timedelta(microseconds=ns // 1000)
    y, m = (d.year + 1, 1) if d.month == 12 else (d.year, d.month + 1)
    d = d.replace(year=y, month=m)
    return calendar.timegm(d.timetuple()) * 1_000_000_000 + d.microsecond * 1000


def walk_fsfat(d, prefix, out, depth=0):
    for i in range(d.number_of_sub_file_entries):
        s = d.get_sub_file_entry(i)
        p = f"{prefix}/{s.name}"
        out.append((p, s))
        if s.file_attribute_flags & 0x10 and depth < 32:
            walk_fsfat(s, p, out, depth + 1)


def test_fat_vs_pyfsfat(images):
    t = Tally()
    n_ours = n_ref = 0
    for label, path in images:
        ours = {o["path"]: o for o in run_jsonl("ls", path, "-r")}
        f = open(path, "rb")
        v = pyfsfat.volume()
        v.open_file_object(f)
        items: list = []
        walk_fsfat(v.get_root_directory(), "", items)
        n_ours += len(ours)
        n_ref += len(items)
        for p, s in items:
            o = ours.get(p)
            ctx = f"{label}:{p}"
            t.add("name_path", o is not None, True, ctx)
            if o is None:
                continue
            t.add("size", o["size"], s.size, ctx)
            t.add("identifier", o["dir_entry_offset"], s.identifier, ctx)
            t.add("attributes", o["attributes"], s.file_attribute_flags, ctx)
            t.add("crtime_raw", o["crtime"], dt_ns(s.get_creation_time()), ctx)
            t.add("mtime_raw", o["mtime"], dt_ns(s.get_modification_time()), ctx)
            t.add("atime_raw", o["atime"], dt_ns(s.get_access_time()), ctx)
            t.add("crtime_month_corrected", add_month(o["crtime"]), dt_ns(s.get_creation_time()), ctx)
            t.add("mtime_month_corrected", add_month(o["mtime"]), dt_ns(s.get_modification_time()), ctx)
            t.add("atime_month_corrected", add_month(o["atime"]), dt_ns(s.get_access_time()), ctx)
        v.close()
        f.close()
    write_result("fs_fat", f"pyfsfat {pyfsfat.get_version()}", [label for label, _ in images], n_ours, n_ref, t,
                 "pyfsfat 20260826 converts FAT dates one calendar month late (raw directory entry: month 4, pyfsfat: "
                 "month 5; pytsk3 and a manual decode agree with veritas-fs). *_raw fields record that disagreement; "
                 "*_month_corrected fields show every other component (year, day, time, 10 ms) agrees exactly.")
    bad = {k: v for k, v in t.fields.items() if v["agree"] != v["total"] and not k.endswith("_raw")}
    assert not bad, (bad, t.mismatches)


def walk_tsk(d, path, out, depth=0):
    for f in d:
        n = f.info.name.name.decode("utf-8", "replace")
        if n in (".", "..") or n in TSK_VIRTUAL or n.endswith("(Volume Label Entry)") or f.info.meta is None:
            continue
        p = f"{path}/{n}"
        out.append((p, f))
        if f.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR and depth < 32:
            try:
                walk_tsk(f.as_directory(), p, out, depth + 1)
            except OSError:
                pass


def tsk_local(ns: int | None) -> int | None:
    """TSK interprets FAT wall-clock times in the host time zone (mktime); apply the same conversion."""
    if ns is None:
        return None
    naive = dt.datetime(1970, 1, 1) + dt.timedelta(seconds=ns // 1_000_000_000)
    return int(time.mktime(naive.timetuple()))


def test_fat_vs_pytsk3(images):
    t = Tally()
    n_ours = n_ref = 0
    for label, path in images:
        ours = {o["path"]: o for o in run_jsonl("ls", path, "-r", "--deleted")}
        fs = pytsk3.FS_Info(pytsk3.Img_Info(str(path)))
        items: list = []
        walk_tsk(fs.open_dir("/"), "", items)
        n_ours += len(ours)
        n_ref += len(items)
        for p, f in items:
            m = f.info.meta
            o = ours.get(p)
            ctx = f"{label}:{p}"
            t.add("name_path", o is not None, True, ctx)
            if o is None:
                continue
            if f.info.name.type != pytsk3.TSK_FS_NAME_TYPE_DIR:
                t.add("size", o["size"], m.size, ctx)
            t.add("is_allocated", not o["deleted"], bool(m.flags & pytsk3.TSK_FS_META_FLAG_ALLOC), ctx)
            t.add("crtime", tsk_local(o["crtime"]), m.crtime or None, ctx)
            t.add("crtime_nano", (o["crtime"] or 0) % 1_000_000_000, m.crtime_nano, ctx)
            t.add("mtime", tsk_local(o["mtime"]), m.mtime or None, ctx)
            t.add("atime", tsk_local(o["atime"]), m.atime or None, ctx)
    write_result("fs_fat_tsk", f"pytsk3 {pytsk3.TSK_VERSION_STR}", [label for label, _ in images], n_ours, n_ref, t,
                 "TSK converts FAT wall-clock times with the host time zone; the comparison applies the same mktime "
                 "conversion. Deleted entries included on both sides. TSK virtual files ($MBR, $FAT1, $FAT2, $OrphanFiles, "
                 "volume label entry) excluded; directory sizes not compared.")
    bad = {k: v for k, v in t.fields.items() if v["agree"] != v["total"]}
    assert not bad, (bad, t.mismatches)
