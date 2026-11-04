"""Parity: veritas-artifacts shell item parser (Rust, ``veritas-artifacts-dump shellitems``) vs libfwsi (pyfwsi).

ID lists compared:
- link target ID lists of every corpus LNK file (liblnk ``link_target_identifier_data``);
- link target ID lists of every LNK embedded in the automatic/custom destination jump lists;
- ShellBags ``BagMRU`` blobs from the corpus NTUSER hives (read with pyregf, when available).

Per list: item count; per item: class category (root folder / volume / file entry / network /
URI / control panel / delegate / other), primary name, 0xbeef0004 long name, FAT modification
time, 0xbeef0004 creation and access times, NTFS file reference and root folder GUID.

Results: parity/results/shellitems.json (format: parity/README.md).
"""

from __future__ import annotations

import importlib.metadata
import io
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

pyfwsi = pytest.importorskip("pyfwsi")
pylnk = pytest.importorskip("pylnk")
pyolecf = pytest.importorskip("pyolecf")

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "testdata" / "corpus" / "plaso"
RESULTS = REPO / "parity" / "results" / "shellitems.json"
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


def category(c: int) -> str:
    if c == 0x1F:
        return "root_folder"
    if 0x20 <= c <= 0x2F:
        return "volume"
    if 0x30 <= c <= 0x3F:
        return "file_entry"
    if 0x40 <= c <= 0x4F:
        return "network_location"
    return {
        0x00: "users_property_view",
        0x01: "control_panel_category",
        0x52: "compressed_folder",
        0x61: "uri",
        0x71: "control_panel",
        0x74: "delegate",
    }.get(c, "other")


OUR_CATEGORY = {"directory": "file_entry", "file": "file_entry", "file_entry": "file_entry", "unknown": "other"}


def fix(s):
    return s.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace") if isinstance(s, str) else s


def iso(dt) -> str | None:
    return None if dt is None else dt.strftime("%Y-%m-%dT%H:%M:%S")


def ns_iso(ns) -> str | None:
    if ns is None:
        return None
    import datetime

    return (datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=ns // 1000)).strftime("%Y-%m-%dT%H:%M:%S")


def lnk_idlist(data: bytes) -> bytes | None:
    l = pylnk.file()
    l.open_file_object(io.BytesIO(data))
    d = l.link_target_identifier_data
    l.close()
    return d


def collect_lists() -> list[tuple[str, bytes]]:
    lists: list[tuple[str, bytes]] = []
    for p in sorted(CORPUS.glob("*.lnk")):
        d = lnk_idlist(p.read_bytes())
        if d:
            lists.append((f"plaso/{p.name}", d))
    for p in sorted((CORPUS / "automaticDestinations-ms").glob("*")):
        o = pyolecf.file()
        o.open(str(p.resolve()))
        root = o.root_item
        for i in range(root.number_of_sub_items):
            it = root.get_sub_item(i)
            if it.name == "DestList":
                continue
            d = lnk_idlist(it.read(it.size))
            if d:
                lists.append((f"plaso/automaticDestinations-ms/{p.name}#{it.name}", d))
        o.close()
    for p in sorted((CORPUS / "customDestinations-ms").glob("*")):
        raw = p.read_bytes()
        pat = LNK_CLSID + b"\x4c\x00\x00\x00" + LNK_CLSID
        pos = raw.find(pat)
        while pos >= 0:
            d = lnk_idlist(raw[pos + 16 :])
            if d:
                lists.append((f"plaso/customDestinations-ms/{p.name}@{pos + 16}", d))
            pos = raw.find(pat, pos + 16)
    try:
        import pyregf
    except ImportError:
        return lists
    for hive in ["NTUSER.DAT", "NTUSER-WIN7.DAT"]:
        if not (CORPUS / hive).exists():
            continue
        f = pyregf.file()
        f.open(str((CORPUS / hive).resolve()))
        for kp in [r"Software\Microsoft\Windows\Shell\BagMRU", r"Software\Microsoft\Windows\ShellNoRoam\BagMRU"]:
            k = f.get_key_by_path(kp)
            stack = [(kp, k)] if k else []
            while stack:
                path, key = stack.pop()
                for v in key.values:
                    if v.name.isdigit() and v.data:
                        lists.append((f"plaso/{hive}:{path}\\{v.name}", v.data))
                for s in key.sub_keys:
                    stack.append((path + "\\" + s.name, s))
        f.close()
    return lists


def reference_items(data: bytes) -> list[dict]:
    il = pyfwsi.item_list()
    il.copy_from_byte_stream(data)
    out = []
    for it in il.items:
        e = {"category": category(it.class_type)}
        if hasattr(it, "shell_folder_identifier"):
            e["class_id"] = it.shell_folder_identifier
        if e["category"] in ("volume", "file_entry", "network_location") and hasattr(it, "name"):
            e["name"] = fix(it.name)
        if e["category"] == "file_entry" and hasattr(it, "modification_time"):
            e["modification_time"] = iso(it.modification_time)
        for b in it.extension_blocks:
            if b.signature == 0xBEEF0004:
                e["long_name"] = fix(getattr(b, "long_name", None))
                e["creation_time"] = iso(getattr(b, "creation_time", None))
                e["access_time"] = iso(getattr(b, "access_time", None))
                e["file_reference"] = getattr(b, "file_reference", None)
        out.append(e)
    return out


def our_items(o: dict) -> list[dict]:
    out = []
    for it in o.get("items", []):
        e = {"category": OUR_CATEGORY.get(it["item_type"], it["item_type"]), "class_id": it["class_id"], "name": it["name"]}
        e["modification_time"] = ns_iso(it["modification_ns"])
        blk = next((b for b in it["extension_blocks"] if b["signature"] == 0xBEEF0004), None)
        if blk:
            e["long_name"] = blk["fields"].get("long_name")
            e["creation_time"] = ns_iso(blk["fields"].get("creation_ns"))
            e["access_time"] = ns_iso(blk["fields"].get("access_ns"))
            e["file_reference"] = blk["fields"].get("file_reference")
        out.append(e)
    return out


def test_shellitems_parity():
    if not (CORPUS / "NeroInfoTool.lnk").exists():
        pytest.skip("corpus missing (python testdata/fetch.py)")
    lists = collect_lists()
    with tempfile.TemporaryDirectory() as td:
        hexfile = Path(td) / "lists.hex"
        hexfile.write_text("\n".join(d.hex() for _, d in lists) + "\n", encoding="ascii")
        ours = dump("shellitems", hexfile)
    assert len(ours) == len(lists)
    fields: dict[str, dict[str, int]] = {}
    mismatches = []
    n_items_ref = n_items_ours = 0

    def agree(f: str, ok: bool, ctx) -> None:
        e = fields.setdefault(f, {"agree": 0, "total": 0})
        e["total"] += 1
        e["agree"] += int(ok)
        if not ok:
            mismatches.append(ctx)

    for (name, data), o in zip(lists, ours):
        ref = reference_items(data)
        mine = our_items(o)
        n_items_ref += len(ref)
        n_items_ours += len(mine)
        agree("item_count", len(ref) == len(mine), (name, "count", len(ref), len(mine)))
        for i, (r, m) in enumerate(zip(ref, mine)):
            for f, v in r.items():
                if f == "class_id" and v is None:
                    continue
                agree(f, m.get(f) == v, (name, i, f, v, m.get(f)))
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "parser": "shellitems",
                "reference": f"libfwsi-python {importlib.metadata.version('libfwsi-python')}",
                "samples": sorted({n.split("#")[0].split("@")[0].split(":")[0] for n, _ in lists}),
                "records_ours": n_items_ours,
                "records_reference": n_items_ref,
                "fields": fields,
                "notes": f"{len(lists)} ID lists (LNK targets, jump-list LNK streams, ShellBags BagMRU blobs). "
                "Times compared at 1 s resolution (FAT); lone surrogates normalized to U+FFFD. "
                + (f"mismatches (first 20): {mismatches[:20]}" if mismatches else ""),
            },
            indent=2,
            ensure_ascii=False,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )
    assert fields["item_count"]["agree"] == fields["item_count"]["total"]
    for f in ("category", "name", "long_name", "modification_time", "file_reference"):
        if f in fields:
            assert fields[f]["agree"] == fields[f]["total"], (f, fields[f], mismatches[:5])
