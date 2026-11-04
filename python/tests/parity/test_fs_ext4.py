"""Parity: veritas-fs ext2/3/4 (fs-tool ls -r) vs pyfsext and pytsk3."""
from __future__ import annotations

import functools
import json
import os
import subprocess
from collections import defaultdict
from pathlib import Path

import pytest

pyfsext = pytest.importorskip("pyfsext")
pytsk3 = pytest.importorskip("pytsk3")

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "testdata" / "corpus"
RESULTS = ROOT / "parity" / "results"
pytestmark = pytest.mark.parity
# (sample, partition index or None, byte offset of the file system)
SAMPLES = [("dfvfs/ext4.raw", None, 0), ("dfvfs/ext2.raw", None, 0), ("plaso/ext4.raw", None, 0), ("plaso/syslog_image.dd", None, 0),
           ("dfvfs/mbr.raw", 0, 512), ("dfvfs/mbr.raw", 1, 131 * 512), ("dfvfs/gpt.raw", 0, 2048 * 512), ("dfvfs/gpt.raw", 1, 4096 * 512),
           ("plaso/tsk_volume_system.raw", 1, 352 * 512)]  # partition 0 holds no file system (TSK agrees)


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


class Window:
    def __init__(self, f, off):
        self.f, self.off, self.pos = f, off, 0
        f.seek(0, 2)
        self.size = f.tell() - off

    def read(self, n=-1):
        n = self.size - self.pos if n is None or n < 0 else min(n, self.size - self.pos)
        self.f.seek(self.off + self.pos)
        d = self.f.read(n)
        self.pos += len(d)
        return d

    def seek(self, o, w=0):
        self.pos = o if w == 0 else (self.pos + o if w == 1 else self.size + o)
        return self.pos

    def tell(self):
        return self.pos

    def get_size(self):
        return self.size


def ours_for(sample, part):
    args = ["ls", CORPUS / sample, "-r"]
    if part is not None:
        args += ["--partition", part]
    return {o["path"]: o for o in run_jsonl(*args)}


def walk_pyfsext(d, prefix, out, depth=0):
    for i in range(d.number_of_sub_file_entries):
        s = d.get_sub_file_entry(i)
        p = f"{prefix}/{s.name}"
        out.append((p, s))
        if (s.file_mode & 0o170000) == 0o040000 and depth < 32:
            walk_pyfsext(s, p, out, depth + 1)


def none0(v):
    return None if v in (0, None) else v


def test_ext_vs_pyfsext():
    t = Tally()
    n_ours = n_ref = 0
    for sample, part, off in SAMPLES:
        ours = ours_for(sample, part)
        f = open(CORPUS / sample, "rb")
        v = pyfsext.volume()
        v.open_file_object(Window(f, off))
        items: list = []
        walk_pyfsext(v.get_root_directory(), "", items)
        n_ours += len(ours)
        n_ref += len(items)
        label = f"{sample}#{part}"
        for p, s in items:
            o = ours.get(p)
            t.add("name_path", o is not None, True, f"{label}:{p}")
            if o is None:
                continue
            ctx = f"{label}:{p}"
            t.add("inode", o["inode"], s.inode_number, ctx)
            if (s.file_mode & 0o170000) != 0o040000:
                t.add("size", o["size"], s.size, ctx)
            t.add("mode", o["mode"], s.file_mode, ctx)
            t.add("uid", o["uid"], s.owner_identifier, ctx)
            t.add("gid", o["gid"], s.group_identifier, ctx)
            t.add("links", o["links"], s.number_of_links, ctx)
            t.add("atime", o["atime"], none0(s.get_access_time_as_integer()), ctx)
            t.add("mtime", o["mtime"], none0(s.get_modification_time_as_integer()), ctx)
            t.add("ctime", o["ctime"], none0(s.get_inode_change_time_as_integer()), ctx)
            t.add("crtime", o["crtime"], none0(s.get_creation_time_as_integer()), ctx)
            t.add("dtime", o["dtime"], s.get_deletion_time_as_integer() // 1_000_000_000 if s.get_deletion_time_as_integer() else 0, ctx)
            if (s.file_mode & 0o170000) == 0o120000:
                t.add("symlink_target", o["symlink_target"], s.symbolic_link_target, ctx)
        v.close()
        f.close()
    write_result("fs_ext4", f"pyfsext {pyfsext.get_version()}", [f"{s}#{p}" for s, p, _ in SAMPLES], n_ours, n_ref, t,
                 "Directory sizes not compared (pyfsext reports 0, i_size is the block-rounded directory length). "
                 "Times are nanoseconds incl. extra-isize; crtime None on 128-byte inodes (ext2).")
    bad = {k: v for k, v in t.fields.items() if v["agree"] != v["total"]}
    assert not bad, (bad, t.mismatches)


def walk_tsk(d, path, out, depth=0):
    for f in d:
        n = f.info.name.name.decode("utf-8", "replace")
        if n in (".", "..", "$OrphanFiles") or f.info.meta is None:
            continue
        p = f"{path}/{n}"
        out.append((p, f))
        if f.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR and depth < 32:
            try:
                walk_tsk(f.as_directory(), p, out, depth + 1)
            except OSError:
                pass


def tsk_ns(sec, nano):
    return sec * 1_000_000_000 + nano if sec else None


def test_ext_vs_pytsk3():
    t = Tally()
    n_ours = n_ref = 0
    for sample, part, off in SAMPLES:
        ours = ours_for(sample, part)
        fs = pytsk3.FS_Info(pytsk3.Img_Info(str(CORPUS / sample)), offset=off)
        items: list = []
        walk_tsk(fs.open_dir("/"), "", items)
        n_ours += len(ours)
        n_ref += len(items)
        for p, f in items:
            m = f.info.meta
            o = ours.get(p)
            ctx = f"{sample}#{part}:{p}"
            t.add("name_path", o is not None, True, ctx)
            if o is None:
                continue
            t.add("inode", o["inode"], m.addr, ctx)
            t.add("size", o["size"], m.size, ctx)
            t.add("is_allocated", o["allocated"], bool(m.flags & pytsk3.TSK_FS_META_FLAG_ALLOC), ctx)
            t.add("atime", o["atime"], tsk_ns(m.atime, m.atime_nano), ctx)
            t.add("mtime", o["mtime"], tsk_ns(m.mtime, m.mtime_nano), ctx)
            t.add("ctime", o["ctime"], tsk_ns(m.ctime, m.ctime_nano), ctx)
            t.add("crtime", o["crtime"], tsk_ns(m.crtime, m.crtime_nano), ctx)
    write_result("fs_ext4_tsk", f"pytsk3 {pytsk3.TSK_VERSION_STR}", [f"{s}#{p}" for s, p, _ in SAMPLES], n_ours, n_ref, t,
                 "TSK lists lost+found and reports directory i_size, both compared.")
    bad = {k: v for k, v in t.fields.items() if v["agree"] != v["total"]}
    assert not bad, (bad, t.mismatches)
