"""Parity: veritas-artifacts EVTX parser (Rust, ``veritas-artifacts-dump evtx``) vs libevtx (pyevtx).

Per record: identifier, written time (microseconds), event identifier, source (provider) name,
computer name, event level, the libevtx string list and ``xml_string`` (compared after
whitespace normalization). libevtx does not list records from chunks whose event-records CRC32
fails; our parser keeps them but flags ``data_crc_ok = false``, so only records from CRC-valid
chunks are compared and the difference is reported in the notes.

Results: parity/results/evtx.json (format: parity/README.md).
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

pyevtx = pytest.importorskip("pyevtx")

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "testdata" / "corpus" / "plaso"
RESULTS = REPO / "parity" / "results" / "evtx.json"
EXE = REPO / "target" / "release" / ("veritas-artifacts-dump.exe" if os.name == "nt" else "veritas-artifacts-dump")
SAMPLES = ["evtx/System.evtx", "evtx/System2.evtx"]
FIELDS = ["identifier", "written_time_us", "event_identifier", "source_name", "computer_name", "event_level", "strings", "xml_string"]

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


def norm_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def test_evtx_parity():
    if not (CORPUS / SAMPLES[0]).exists():
        pytest.skip("corpus missing (python testdata/fetch.py)")
    fields = {f: {"agree": 0, "total": 0} for f in FIELDS}
    ours_n = ref_n = flagged = 0
    for rel in SAMPLES:
        path = CORPUS / rel
        lines = dump("evtx", path)
        records = [r for r in lines[1:] if r["header_crc_ok"] and r["data_crc_ok"]]
        flagged += len(lines) - 1 - len(records)
        ev = pyevtx.file()
        ev.open(str(path.resolve()))
        n = ev.number_of_records
        ours_n += len(records)
        ref_n += n
        for i in range(min(n, len(records))):
            r = ev.get_record(i)
            o = records[i]
            ref = {
                "identifier": r.identifier,
                "written_time_us": r.get_written_time_as_integer() // 10,
                "event_identifier": r.event_identifier,
                "source_name": r.source_name,
                "computer_name": r.computer_name,
                "event_level": r.event_level,
                "strings": [r.get_string(k) or "" for k in range(r.number_of_strings)],
                "xml_string": norm_ws(r.xml_string),
            }
            mine = {
                "identifier": o["identifier"],
                "written_time_us": o["written_filetime"] // 10,
                "event_identifier": o["event_id"],
                "source_name": o["source_name"],
                "computer_name": o["computer"],
                "event_level": o["level"],
                "strings": o["strings"],
                "xml_string": norm_ws(o["xml"]),
            }
            for f in FIELDS:
                fields[f]["total"] += 1
                fields[f]["agree"] += int(ref[f] == mine[f])
        ev.close()
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "parser": "evtx",
                "reference": f"libevtx-python {importlib.metadata.version('libevtx-python')}",
                "samples": [f"plaso/{s}" for s in SAMPLES],
                "records_ours": ours_n,
                "records_reference": ref_n,
                "fields": fields,
                "notes": (
                    f"{flagged} additional records (System2.evtx chunk 2, event-records CRC32 mismatch) are parsed and "
                    "flagged data_crc_ok=false by Veritas; libevtx omits them, so they are excluded from the comparison. "
                    "xml_string compared after collapsing whitespace. Empty libevtx strings (None) compared as ''."
                ),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    assert ours_n == ref_n
    for f in FIELDS:
        assert fields[f]["agree"] == fields[f]["total"], (f, fields[f])
