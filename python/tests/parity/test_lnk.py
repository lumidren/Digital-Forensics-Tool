"""Parity: veritas-artifacts LNK parser (Rust, ``veritas-artifacts-dump lnk``) vs liblnk (pylnk).

Per file: creation/modification/access FILETIMEs, file size, data flags, local path, network
path, description, relative path, working directory, command line arguments, icon location,
environment variables location, drive type, drive serial number, volume label, machine
identifier and the four droid identifiers.

pylnk returns lone UTF-16 surrogates (unpaired_surrogate.lnk) as Python surrogate code points;
Rust strings cannot hold them and substitute U+FFFD, so reference strings are normalized the
same way before comparing.

Results: parity/results/lnk.json (format: parity/README.md).
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import subprocess
from pathlib import Path

import pytest

pylnk = pytest.importorskip("pylnk")

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "testdata" / "corpus" / "plaso"
RESULTS = REPO / "parity" / "results" / "lnk.json"
EXE = REPO / "target" / "release" / ("veritas-artifacts-dump.exe" if os.name == "nt" else "veritas-artifacts-dump")
SAMPLES = ["NeroInfoTool.lnk", "example.lnk", "unpaired_surrogate.lnk"]

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


def fix(s):
    if isinstance(s, str):
        return s.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")
    return s


def reference(l) -> dict:
    return {
        "creation_time": l.get_file_creation_time_as_integer(),
        "modification_time": l.get_file_modification_time_as_integer(),
        "access_time": l.get_file_access_time_as_integer(),
        "file_size": l.file_size,
        "data_flags": l.data_flags,
        "local_path": fix(l.local_path),
        "network_path": fix(l.network_path),
        "description": fix(l.description),
        "relative_path": fix(l.relative_path),
        "working_directory": fix(l.working_directory),
        "command_line_arguments": fix(l.command_line_arguments),
        "icon_location": fix(l.icon_location),
        "environment_variables_location": fix(l.environment_variables_location),
        "drive_type": l.drive_type,
        "drive_serial_number": l.drive_serial_number,
        "volume_label": fix(l.volume_label),
        "machine_identifier": l.machine_identifier,
        "droid_volume_identifier": l.droid_volume_identifier,
        "droid_file_identifier": l.droid_file_identifier,
        "birth_droid_volume_identifier": l.birth_droid_volume_identifier,
        "birth_droid_file_identifier": l.birth_droid_file_identifier,
    }


def ours(o: dict) -> dict:
    li = o.get("link_info") or {}
    t = o.get("tracker") or {}
    return {
        "creation_time": o["creation_filetime"],
        "modification_time": o["modification_filetime"],
        "access_time": o["access_filetime"],
        "file_size": o["file_size"],
        "data_flags": o["link_flags"],
        "local_path": o["local_path"],
        "network_path": o["network_path"],
        "description": o["description"],
        "relative_path": o["relative_path"],
        "working_directory": o["working_directory"],
        "command_line_arguments": o["command_line_arguments"],
        "icon_location": o["icon_location"],
        "environment_variables_location": o["environment_variables_location"],
        "drive_type": li.get("drive_type"),
        "drive_serial_number": li.get("drive_serial_number"),
        "volume_label": li.get("volume_label"),
        "machine_identifier": t.get("machine_identifier"),
        "droid_volume_identifier": t.get("droid_volume_identifier"),
        "droid_file_identifier": t.get("droid_file_identifier"),
        "birth_droid_volume_identifier": t.get("birth_droid_volume_identifier"),
        "birth_droid_file_identifier": t.get("birth_droid_file_identifier"),
    }


def test_lnk_parity():
    if not (CORPUS / SAMPLES[0]).exists():
        pytest.skip("corpus missing (python testdata/fetch.py)")
    fields: dict[str, dict[str, int]] = {}
    mismatches = []
    for rel in SAMPLES:
        path = CORPUS / rel
        l = pylnk.file()
        l.open(str(path.resolve()))
        ref = reference(l)
        l.close()
        mine = ours(dump("lnk", path)[0])
        for k, v in ref.items():
            e = fields.setdefault(k, {"agree": 0, "total": 0})
            e["total"] += 1
            if mine[k] == v:
                e["agree"] += 1
            else:
                mismatches.append((rel, k, v, mine[k]))
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "parser": "lnk",
                "reference": f"liblnk-python {importlib.metadata.version('liblnk-python')}",
                "samples": [f"plaso/{s}" for s in SAMPLES],
                "records_ours": len(SAMPLES),
                "records_reference": len(SAMPLES),
                "fields": fields,
                "notes": "Lone UTF-16 surrogates in pylnk strings are normalized to U+FFFD before comparison "
                "(Rust String cannot represent them). " + (f"mismatches: {mismatches}" if mismatches else ""),
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    assert not mismatches, mismatches
