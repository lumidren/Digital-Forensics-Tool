"""Parity: our PE report (pefile-based) vs LIEF (an independent C++ PE parser).

Compared per sample: machine, compile timestamp, entry point, subsystem, DLL flag, section names,
virtual/raw sizes, section entropy (milli-bits, +/-1 for rounding), imported DLLs and function
names, imphash and Authenticode presence. Results go to parity/results/pe.json.
"""
from __future__ import annotations

import json
from pathlib import Path

import lief
import pefile
import pytest

from veritas.malware.static import StaticAnalyzer, entropy_milli

pytestmark = pytest.mark.parity
REPO = Path(__file__).resolve().parents[3]
RESULTS = REPO / "parity" / "results" / "pe.json"
SAMPLES = ["plaso/test_pe.exe", "plaso/test_driver.sys"]


def _lief_view(path: Path) -> dict:
    lief.logging.disable()
    b = lief.PE.parse(str(path))
    imports = []
    for imp in b.imports:
        imports.append((imp.name, [e.name if not e.is_ordinal else f"ord{e.ordinal}" for e in imp.entries]))
    return {
        "machine": int(b.header.machine.value),
        "timestamp": b.header.time_date_stamps,
        "entry_point": b.optional_header.addressof_entrypoint,
        "subsystem": int(b.optional_header.subsystem.value),
        "is_dll": b.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL),
        "sections": [(s.name, s.virtual_size, s.sizeof_raw_data, int(round(s.entropy * 1000))) for s in b.sections],
        "imports": imports,
        "imphash": lief.PE.get_imphash(b, lief.PE.IMPHASH_MODE.PEFILE),
        "signed": b.has_signatures,
    }


def _our_view(path: Path) -> dict:
    rep = StaticAnalyzer().analyze(str(path))
    data = path.read_bytes()
    hdr = rep["header"]
    machine = next(k for k, v in pefile.MACHINE_TYPE.items() if v == hdr["machine"] and isinstance(k, int))
    subsystem = next(k for k, v in pefile.SUBSYSTEM_TYPE.items() if v == hdr["subsystem"] and isinstance(k, int))
    return {
        "machine": machine, "timestamp": hdr["timestamp"], "entry_point": hdr["entry_point"], "subsystem": subsystem,
        "is_dll": hdr["is_dll"],
        # Our report follows pefile: entropy over the raw (file-aligned) section bytes. LIEF measures
        # the in-memory content, i.e. the first min(virtual size, raw size) bytes; recompute ours on
        # that range so the comparison checks section extraction and the entropy maths, not the convention.
        "sections": [(s["name"], s["virtual_size"], s["raw_size"],
                      entropy_milli(data[s["raw_offset"]:s["raw_offset"] + min(s["virtual_size"] or s["raw_size"], s["raw_size"])]))
                     for s in rep["sections"]],
        "imports": [(i["dll"], i["functions"]) for i in rep["imports"]],
        "imphash": rep["imphash"], "signed": rep["signature"]["present"],
    }


def test_pe_parity_vs_lief(corpus):
    fields: dict[str, dict[str, int]] = {}
    notes = []

    def agree(name, ok):
        f = fields.setdefault(name, {"agree": 0, "total": 0})
        f["total"] += 1
        f["agree"] += int(bool(ok))

    for rel in SAMPLES:
        path = corpus / rel
        if not path.is_file():
            pytest.skip(f"{rel} not in corpus")
        ours, ref = _our_view(path), _lief_view(path)
        for k in ("machine", "timestamp", "entry_point", "subsystem", "is_dll", "imphash", "signed"):
            agree(k, ours[k] == ref[k])
        agree("section_count", len(ours["sections"]) == len(ref["sections"]))
        for (n1, v1, r1, e1), (n2, v2, r2, e2) in zip(ours["sections"], ref["sections"]):
            agree("section_name", n1 == n2)
            agree("section_sizes", (v1, r1) == (v2, r2))
            agree("section_entropy_milli", abs(e1 - e2) <= 1)
        ref_imp = {d.lower(): f for d, f in ref["imports"]}
        for dll, funcs in ours["imports"]:
            agree("import_dlls", dll.lower() in ref_imp)
            agree("import_functions", sorted(funcs) == sorted(ref_imp.get(dll.lower(), [])))
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({
        "parser": "pe_static", "reference": f"lief {lief.__version__}", "samples": SAMPLES,
        "records_ours": len(SAMPLES), "records_reference": len(SAMPLES), "fields": fields,
        "notes": "; ".join(notes) or ("delay imports are not compared (LIEF exposes them separately); section entropy compared over "
                                    "LIEF's in-memory range (reports use pefile's raw-size convention)"),
    }, indent=2) + "\n", encoding="utf-8")
    for name, f in fields.items():
        assert f["agree"] == f["total"], (name, f)
