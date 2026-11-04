"""Parity: veritas-artifacts prefetch parser (Rust, ``veritas-artifacts-dump prefetch``) vs libscca (pyscca).

Per file: executable filename, prefetch hash, run count, format version, each last run time
(raw FILETIME), the full file name list, and per volume the device path, serial number and
creation time. Covers SCCA versions 17, 23, 26, 30 and 31 (the latter two MAM/LZXPRESS
Huffman compressed).

Results: parity/results/prefetch.json (format: parity/README.md).
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import subprocess
from pathlib import Path

import pytest

pyscca = pytest.importorskip("pyscca")

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "testdata" / "corpus" / "plaso"
RESULTS = REPO / "parity" / "results" / "prefetch.json"
EXE = REPO / "target" / "release" / ("veritas-artifacts-dump.exe" if os.name == "nt" else "veritas-artifacts-dump")
FIELDS = [
    "executable_name", "prefetch_hash", "run_count", "format_version", "last_run_times",
    "filenames", "volume_device_paths", "volume_serial_numbers", "volume_creation_times",
]

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


def test_prefetch_parity():
    files = sorted((CORPUS / "winprefetch").glob("*.pf"))
    if not files:
        pytest.skip("corpus missing (python testdata/fetch.py)")
    fields = {f: {"agree": 0, "total": 0} for f in FIELDS}
    versions = set()

    def agree(f: str, ok: bool) -> None:
        fields[f]["total"] += 1
        fields[f]["agree"] += int(ok)

    for path in files:
        o = dump("prefetch", path)[0]
        s = pyscca.file()
        s.open(str(path.resolve()))
        versions.add(s.format_version)
        n_runs = 8 if s.format_version >= 26 else 1
        ref_runs = [t for t in (s.get_last_run_time_as_integer(i) for i in range(n_runs)) if t]
        vols = [s.get_volume_information(i) for i in range(s.number_of_volumes)]
        agree("executable_name", o["executable_filename"] == s.executable_filename)
        agree("prefetch_hash", o["prefetch_hash"] == s.prefetch_hash)
        agree("run_count", o["run_count"] == s.run_count)
        agree("format_version", o["version"] == s.format_version)
        for i, t in enumerate(ref_runs):
            agree("last_run_times", i < len(o["last_run_filetimes"]) and o["last_run_filetimes"][i] == t)
        if len(o["last_run_filetimes"]) != len(ref_runs):
            agree("last_run_times", False)
        agree("filenames", [m["filename"] for m in o["file_metrics"]] == [s.get_filename(i) for i in range(s.number_of_filenames)])
        agree("volume_device_paths", [v["device_path"] for v in o["volumes"]] == [v.device_path for v in vols])
        agree("volume_serial_numbers", [v["serial_number"] for v in o["volumes"]] == [v.serial_number for v in vols])
        agree("volume_creation_times", [v["creation_filetime"] for v in o["volumes"]] == [v.get_creation_time_as_integer() for v in vols])
        s.close()
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "parser": "prefetch",
                "reference": f"libscca-python {importlib.metadata.version('libscca-python')}",
                "samples": [f"plaso/winprefetch/{p.name}" for p in files],
                "records_ours": len(files),
                "records_reference": len(files),
                "fields": fields,
                "notes": f"format versions covered: {sorted(versions)}; versions 30/31 are MAM\\x04 (LZXPRESS Huffman) compressed. "
                "last_run_times counts each non-zero run time individually.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    for f in FIELDS:
        assert fields[f]["agree"] == fields[f]["total"], (f, fields[f])
