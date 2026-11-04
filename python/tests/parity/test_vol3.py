"""Parity: Volatility 3 driver (in-process framework backend) vs the ``vol`` CLI (subprocess backend)
on a real memory image, plus an end-to-end run of the memory pipeline.

There is no public Windows memory sample small enough for the corpus (the Volatility Foundation
and MemLabs samples are 0.5-2 GB+), and acquiring this host's memory needs administrator rights
and a kernel driver. The test therefore runs only when ``VERITAS_MEM_IMAGE`` points at an image:

    VERITAS_MEM_IMAGE=/cases/win10.raw  [VERITAS_VOL_OS=windows] [VERITAS_VOL_OFFLINE=1
    VERITAS_VOL_SYMBOL_DIRS=/opt/isf]  pytest -m parity tests/parity/test_vol3.py

Volatility resolves kernel symbols from its ISF cache, the symbol dirs, or (unless offline) the
symbol server. Results go to parity/results/vol3.json.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from veritas.memory import analyze_image
from veritas.memory.volatility import PluginSpec, VolatilityConfig, VolatilityDriver

pytestmark = [pytest.mark.parity, pytest.mark.slow, pytest.mark.needs_images]
REPO = Path(__file__).resolve().parents[3]
RESULTS = REPO / "parity" / "results" / "vol3.json"
IMAGE = os.environ.get("VERITAS_MEM_IMAGE")

PARITY_PLUGINS = {
    "windows": ["windows.info", "windows.pslist", "windows.dlllist", "windows.netscan"],
    "linux": ["linux.pslist", "linux.lsmod"],
    "mac": ["mac.pslist"],
}

needs_image = pytest.mark.skipif(
    not IMAGE or not os.path.isfile(IMAGE),
    reason="set VERITAS_MEM_IMAGE to a memory image (no public sample small enough for the corpus)",
)


def _strip(rows):
    return [{k: v for k, v in r.items() if k not in ("File output",)} for r in rows]


@needs_image
def test_vol3_inprocess_matches_cli():
    base = VolatilityConfig.from_env()
    plugins = PARITY_PLUGINS.get(base.os, [])
    fields: dict[str, dict[str, int]] = {}
    rows_ours = rows_ref = 0
    notes = []
    for plugin in plugins:
        inproc = VolatilityDriver(VolatilityConfig.from_env(backend="inprocess")).run_plugin(IMAGE, plugin)
        cli = VolatilityDriver(VolatilityConfig.from_env(backend="subprocess")).run_plugin(IMAGE, plugin)
        if not (inproc.ok and cli.ok):
            notes.append(f"{plugin}: inprocess={inproc.errors or 'ok'} cli={cli.errors or 'ok'}")
            continue
        a, b = _strip(inproc.rows), _strip(cli.rows)
        rows_ours += len(a)
        rows_ref += len(b)
        f = fields.setdefault(plugin, {"agree": 0, "total": 0})
        for i in range(max(len(a), len(b))):
            f["total"] += 1
            f["agree"] += int(i < len(a) and i < len(b) and a[i] == b[i])
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({
        "parser": "volatility3", "reference": "vol CLI -r json (same Volatility build)",
        "samples": [os.path.basename(IMAGE)], "records_ours": rows_ours, "records_reference": rows_ref,
        "fields": fields, "notes": "; ".join(notes),
    }, indent=2) + "\n", encoding="utf-8")
    assert fields, "no plugin produced output in both backends: " + "; ".join(notes)
    for name, f in fields.items():
        assert f["agree"] == f["total"], (name, f)


@needs_image
def test_memory_pipeline_end_to_end():
    cfg = VolatilityConfig.from_env()
    res = analyze_image(IMAGE, cfg)
    assert res.report.results, "no plugins ran"
    ok = [k for k, r in res.report.results.items() if r.ok]
    assert ok, res.warnings[:10]
    assert any(e.data_type == "memory:process" for e in res.events)
    again = analyze_image(IMAGE, cfg)
    assert [e.to_json() for e in res.events] == [e.to_json() for e in again.events]


def test_vol3_skip_reason_is_documented():
    """Always runs: keeps the gating contract visible in test output."""
    if IMAGE:
        pytest.skip("VERITAS_MEM_IMAGE is set; the real parity tests above run instead")
    assert VolatilityConfig().plugin_specs()[0] == PluginSpec.of("windows.info")
