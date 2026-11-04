"""Parity: veritas-artifacts plist parser (Rust, ``veritas-artifacts-dump plist``) vs Python ``plistlib``.

Every corpus plist (binary and XML) is parsed by both; the trees are compared leaf by leaf
(dates at microsecond resolution as plistlib rounds them, bytes as hex, UIDs as integers,
reals numerically). Fields: whole-document equality and per-leaf agreement.

Results: parity/results/plist.json (format: parity/README.md).
"""

from __future__ import annotations

import datetime
import json
import os
import platform
import plistlib
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "testdata" / "corpus" / "plaso"
RESULTS = REPO / "parity" / "results" / "plist.json"
EXE = REPO / "target" / "release" / ("veritas-artifacts-dump.exe" if os.name == "nt" else "veritas-artifacts-dump")
EPOCH = datetime.datetime(1970, 1, 1)

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


def ours_to_py(v):
    if isinstance(v, dict):
        if "__bytes__" in v:
            return ("bytes", v["__bytes__"])
        if "__date_ns__" in v:
            return ("date", round(v["__date_ns__"] / 1000))
        if "__real__" in v:
            return ("real", float(v["__real__"]))
        if "__uid__" in v:
            return ("uid", v["__uid__"])
        if "__set__" in v:
            return [ours_to_py(x) for x in v["__set__"]]
        if "__int__" in v:
            return int(v["__int__"])
        return {k: ours_to_py(x) for k, x in v.items()}
    if isinstance(v, list):
        return [ours_to_py(x) for x in v]
    return v


def ref_to_py(v):
    if isinstance(v, dict):
        return {k: ref_to_py(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [ref_to_py(x) for x in v]
    if isinstance(v, bytes):
        return ("bytes", v.hex())
    if isinstance(v, datetime.datetime):
        if v.tzinfo:
            v = v.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        d = v - EPOCH
        return ("date", (d.days * 86400 + d.seconds) * 1_000_000 + d.microseconds)
    if isinstance(v, plistlib.UID):
        return ("uid", v.data)
    if isinstance(v, float):
        return ("real", v)
    return v


def leaves(v, path=""):
    if isinstance(v, dict):
        for k in sorted(v):
            yield from leaves(v[k], f"{path}/{k}")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from leaves(x, f"{path}/{i}")
        if not v:
            yield path, "[]"
    else:
        yield path, v


def test_plist_parity():
    files = sorted(list((CORPUS / "plist").glob("*.plist")) + list((CORPUS / "ios").glob("*.plist")))
    if not files:
        pytest.skip("corpus missing (python testdata/fetch.py)")
    fields = {"document_equal": {"agree": 0, "total": 0}, "leaf_values": {"agree": 0, "total": 0}}
    mismatches = []
    for p in files:
        ref = ref_to_py(plistlib.loads(p.read_bytes()))
        mine = ours_to_py(dump("plist", p)[0]["value"])
        fields["document_equal"]["total"] += 1
        fields["document_equal"]["agree"] += int(ref == mine)
        ref_leaves = dict(leaves(ref))
        my_leaves = dict(leaves(mine))
        for k, v in ref_leaves.items():
            fields["leaf_values"]["total"] += 1
            if my_leaves.get(k, "<missing>") == v:
                fields["leaf_values"]["agree"] += 1
            else:
                mismatches.append((p.name, k, v, my_leaves.get(k, "<missing>")))
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "parser": "plist",
                "reference": f"CPython {platform.python_version()} plistlib",
                "samples": [str(p.relative_to(CORPUS.parent)).replace("\\", "/") for p in files],
                "records_ours": len(files),
                "records_reference": len(files),
                "fields": fields,
                "notes": "Dates compared in microseconds (plistlib resolution); reals compared numerically. "
                + (f"mismatches: {mismatches[:20]}" if mismatches else ""),
            },
            indent=2,
            ensure_ascii=False,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )
    assert not mismatches, mismatches[:10]
