"""Parity: veritas-artifacts systemd journal parser (Rust, ``veritas-artifacts-dump journald``)
vs an independent pure-Python journal reader implemented below.

libsystemd / ``journalctl`` are not available on Windows, so the reference is a minimal reader
written from the systemd journal file format documentation (header, entry array chain, entry
items, data objects, regular and compact layouts). It decodes LZ4 data objects with its own
LZ4 block decoder and XZ data objects with Python's ``lzma``; ZSTD objects are unsupported by
both sides (no zstd module in the standard library).

Fields: entry count, seqnum, realtime timestamp (microseconds) and MESSAGE. MESSAGE totals
include entries whose MESSAGE is XZ compressed: Veritas reports those as unsupported (no XZ
decoder in the Rust crate), so they count as disagreements and are listed in the notes.

Results: parity/results/journald.json (format: parity/README.md).
"""

from __future__ import annotations

import json
import lzma
import os
import struct
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "testdata" / "corpus" / "plaso" / "systemd" / "journal"
RESULTS = REPO / "parity" / "results" / "journald.json"
EXE = REPO / "target" / "release" / ("veritas-artifacts-dump.exe" if os.name == "nt" else "veritas-artifacts-dump")

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


# ------------------------------------------------------------------ independent reference reader


def lz4_block(src: bytes, size: int) -> bytes:
    out = bytearray()
    i = 0
    while i < len(src):
        tok = src[i]
        i += 1
        lit = tok >> 4
        if lit == 15:
            while True:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        out += src[i : i + lit]
        i += lit
        if i >= len(src):
            break
        off = src[i] | (src[i + 1] << 8)
        i += 2
        ml = tok & 15
        if ml == 15:
            while True:
                b = src[i]
                i += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        start = len(out) - off
        for k in range(ml):
            out.append(out[start + k])
    assert len(out) == size
    return bytes(out)


def read_journal(d: bytes) -> list[dict]:
    assert d[:8] == b"LPKSHHRH"
    (incompat,) = struct.unpack_from("<I", d, 12)
    compact = bool(incompat & 16)
    (n_entries,) = struct.unpack_from("<Q", d, 152)
    (arr,) = struct.unpack_from("<Q", d, 176)
    offsets: list[int] = []
    seen = set()
    while arr and arr not in seen and len(offsets) < n_entries:
        seen.add(arr)
        typ = d[arr]
        (size,) = struct.unpack_from("<Q", d, arr + 8)
        if typ != 6:
            break
        (nxt,) = struct.unpack_from("<Q", d, arr + 16)
        isz = 4 if compact else 8
        for k in range((size - 24) // isz):
            (v,) = struct.unpack_from("<I" if compact else "<Q", d, arr + 24 + k * isz)
            if v == 0 or len(offsets) >= n_entries:
                break
            offsets.append(v)
        arr = nxt
    entries = []
    for off in offsets:
        if off + 64 > len(d) or d[off] != 3:
            continue
        (size,) = struct.unpack_from("<Q", d, off + 8)
        seq, rt = struct.unpack_from("<QQ", d, off + 16)
        fields: dict[str, str] = {}
        unsupported = 0
        isz = 4 if compact else 16
        for k in range((size - 64) // isz):
            (doff,) = struct.unpack_from("<I" if compact else "<Q", d, off + 64 + k * isz)
            if doff + 16 > len(d) or d[doff] != 1:
                continue
            flags = d[doff + 1]
            (dsize,) = struct.unpack_from("<Q", d, doff + 8)
            hdr = 72 if compact else 64
            payload = d[doff + hdr : doff + dsize]
            if flags & 2:
                (usz,) = struct.unpack_from("<Q", payload, 0)
                payload = lz4_block(payload[8:], usz)
            elif flags & 1:
                payload = lzma.decompress(payload)
            elif flags & 4:
                unsupported += 1
                continue
            if b"=" in payload:
                k_, v_ = payload.split(b"=", 1)
                fields.setdefault(k_.decode("utf-8", "replace"), v_.decode("utf-8", "replace"))
        entries.append({"seqnum": seq, "realtime": rt, "fields": fields, "unsupported": unsupported})
    return entries


# ------------------------------------------------------------------ test


def test_journald_parity():
    files = sorted(p for p in CORPUS.glob("*") if p.is_file()) if CORPUS.exists() else []
    if not files:
        pytest.skip("corpus missing (python testdata/fetch.py)")
    fields = {f: {"agree": 0, "total": 0} for f in ("entry_count", "seqnum", "realtime", "message")}
    ours_n = ref_n = 0
    xz_missing = 0
    for p in files:
        ref = read_journal(p.read_bytes())
        lines = dump("journald", p)
        ours = lines[1:]
        ref_n += len(ref)
        ours_n += len(ours)
        fields["entry_count"]["total"] += 1
        fields["entry_count"]["agree"] += int(len(ref) == len(ours))
        for r, o in zip(ref, ours):
            for f, a, b in (("seqnum", r["seqnum"], o["seqnum"]), ("realtime", r["realtime"], o["realtime_us"])):
                fields[f]["total"] += 1
                fields[f]["agree"] += int(a == b)
            if "MESSAGE" in r["fields"]:
                fields["message"]["total"] += 1
                mine = (o["fields"].get("MESSAGE") or [None])[0]
                if mine == r["fields"]["MESSAGE"]:
                    fields["message"]["agree"] += 1
                elif mine is None and any("xz" in u for u in o["unsupported"]):
                    xz_missing += 1
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "parser": "journald",
                "reference": "independent pure-Python journal reader (python/tests/parity/test_journald.py); "
                "systemd/journalctl not available on Windows",
                "samples": [f"plaso/systemd/journal/{p.name}" for p in files],
                "records_ours": ours_n,
                "records_reference": ref_n,
                "fields": fields,
                "notes": f"{xz_missing} MESSAGE fields are XZ-compressed: the reference decodes them with lzma, Veritas "
                "reports them as unsupported_fields (no XZ decoder in the Rust crate). ZSTD data objects "
                "(user-1000.journal) are unsupported by both. The dirty journal (.journal~) has 45 entry-array "
                "references to zeroed objects that both readers skip.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    for f in ("entry_count", "seqnum", "realtime"):
        assert fields[f]["agree"] == fields[f]["total"], (f, fields[f])
    assert fields["message"]["agree"] + xz_missing == fields["message"]["total"]
