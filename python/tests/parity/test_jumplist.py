"""Parity: veritas-artifacts jump list parser (Rust, ``veritas-artifacts-dump jumplist``) vs
libolecf (pyolecf) stream enumeration + liblnk (pylnk) per embedded link.

AutomaticDestinations: root stream names, per-stream size, per-stream LNK local path,
modification time and file size (pylnk on the stream bytes), and the DestList entries parsed
independently here from the DestList stream bytes read through pyolecf (entry count, entry
number, path, last modification FILETIME, pin status).
CustomDestinations (not OLECF): embedded links located by the LNK class identifier followed
by a shell link header; count, local path, description and file size per link via pylnk.

Results: parity/results/jumplist.json (format: parity/README.md).
"""

from __future__ import annotations

import importlib.metadata
import io
import json
import os
import struct
import subprocess
from pathlib import Path

import pytest

pyolecf = pytest.importorskip("pyolecf")
pylnk = pytest.importorskip("pylnk")

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "testdata" / "corpus" / "plaso"
RESULTS = REPO / "parity" / "results" / "jumplist.json"
EXE = REPO / "target" / "release" / ("veritas-artifacts-dump.exe" if os.name == "nt" else "veritas-artifacts-dump")
LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")

pytestmark = pytest.mark.parity
_built = False


def dump(kind: str, path: Path) -> list[dict]:
    global _built
    if not _built:
        try:
            subprocess.run(["cargo", "build", "-q", "-p", "veritas-artifacts", "--release"], cwd=REPO, check=True)
        except FileNotFoundError:
            if not EXE.exists():
                pytest.skip("cargo not available and dump binary missing")
        _built = True
    out = subprocess.run([str(EXE), kind, str(path)], capture_output=True, check=True)
    return [json.loads(line) for line in out.stdout.decode("utf-8").splitlines() if line.strip()]


def destlist(d: bytes) -> list[dict]:
    """Independent DestList reader (format per libyal jump list documentation)."""
    version, count = struct.unpack_from("<II", d, 0)
    off, out = 32, []
    for _ in range(count):
        path_off = 112 if version < 2 else 128
        (plen,) = struct.unpack_from("<H", d, off + path_off)
        path = d[off + path_off + 2 : off + path_off + 2 + plen * 2].decode("utf-16-le", "replace")
        (num,) = struct.unpack_from("<I", d, off + 88)
        (ft,) = struct.unpack_from("<Q", d, off + 100)
        (pin,) = struct.unpack_from("<i", d, off + 108)
        out.append({"entry_number": num, "path": path, "last_modification_filetime": ft, "pin_status": pin})
        off += path_off + 2 + plen * 2 + (0 if version < 2 else 4)
    return out


def lnk_view(data: bytes) -> dict:
    l = pylnk.file()
    l.open_file_object(io.BytesIO(data))
    v = {"local_path": l.local_path, "modification_time": l.get_file_modification_time_as_integer(), "file_size": l.file_size, "description": l.description}
    l.close()
    return v


def test_jumplist_parity():
    autos = sorted((CORPUS / "automaticDestinations-ms").glob("*"))
    customs = sorted((CORPUS / "customDestinations-ms").glob("*"))
    if not autos:
        pytest.skip("corpus missing (python testdata/fetch.py)")
    fields: dict[str, dict[str, int]] = {}
    mismatches = []
    ours_n = ref_n = 0

    def agree(f: str, ok: bool, ctx) -> None:
        e = fields.setdefault(f, {"agree": 0, "total": 0})
        e["total"] += 1
        e["agree"] += int(ok)
        if not ok:
            mismatches.append(ctx)

    for p in autos:
        o = dump("jumplist", p)[0]["data"]
        f = pyolecf.file()
        f.open(str(p.resolve()))
        root = f.root_item
        subs = [root.get_sub_item(i) for i in range(root.number_of_sub_items)]
        agree("stream_names", sorted(s.name for s in subs) == sorted([s["name"] for s in o["streams"]] + ["DestList"]), (p.name, "names"))
        ours_streams = {s["name"]: s for s in o["streams"]}
        for s in subs:
            data = s.read(s.size)
            if s.name == "DestList":
                ref = destlist(data)
                mine = o["dest_list"]["entries"]
                agree("destlist_entry_count", len(ref) == len(mine), (p.name, "count", len(ref), len(mine)))
                ref_n += len(ref)
                ours_n += len(mine)
                for r, m in zip(ref, mine):
                    for k in r:
                        agree(f"destlist_{k}", r[k] == m[k], (p.name, k, r[k], m[k]))
                continue
            m = ours_streams.get(s.name)
            agree("stream_size", m is not None and m["size"] == s.size, (p.name, s.name, "size"))
            ref = lnk_view(data)
            lk = (m or {}).get("lnk") or {}
            agree("lnk_local_path", m is not None and m.get("local_path") == ref["local_path"], (p.name, s.name, ref["local_path"], m and m.get("local_path")))
            agree("lnk_modification_time", lk.get("modification_filetime") == ref["modification_time"], (p.name, s.name, "mtime"))
            agree("lnk_file_size", lk.get("file_size") == ref["file_size"], (p.name, s.name, "size"))
        f.close()
    for p in customs:
        raw = p.read_bytes()
        pat = LNK_CLSID + b"\x4c\x00\x00\x00" + LNK_CLSID
        offs, pos = [], raw.find(pat)
        while pos >= 0:
            offs.append(pos + 16)
            pos = raw.find(pat, pos + 16)
        o = dump("jumplist", p)[0]["data"]
        agree("custom_entry_count", len(offs) == len(o["entries"]), (p.name, len(offs), len(o["entries"])))
        ref_n += len(offs)
        ours_n += len(o["entries"])
        for off, m in zip(offs, o["entries"]):
            ref = lnk_view(raw[off:])
            agree("custom_offset", m["offset"] == off, (p.name, off, m["offset"]))
            agree("custom_local_path", m["local_path"] == ref["local_path"], (p.name, off, "path"))
            agree("custom_description", m["lnk"]["description"] == ref["description"], (p.name, off, "desc"))
            agree("custom_file_size", m["lnk"]["file_size"] == ref["file_size"], (p.name, off, "size"))
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "parser": "jumplist",
                "reference": f"libolecf-python {importlib.metadata.version('libolecf-python')} + liblnk-python {importlib.metadata.version('liblnk-python')}",
                "samples": [f"plaso/automaticDestinations-ms/{p.name}" for p in autos] + [f"plaso/customDestinations-ms/{p.name}" for p in customs],
                "records_ours": ours_n,
                "records_reference": ref_n,
                "fields": fields,
                "notes": "records = DestList entries + CustomDestinations links. DestList reference is an independent "
                "Python reader over the pyolecf stream bytes. " + (f"mismatches: {mismatches[:20]}" if mismatches else ""),
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    assert not mismatches, mismatches[:10]
