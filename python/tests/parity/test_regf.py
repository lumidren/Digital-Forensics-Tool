"""Parity: veritas-artifacts REGF parser (Rust) against libregf (pyregf) and dissect.regf.

Our view of each hive is produced by the ignored Rust test
``crates/veritas-artifacts/tests/regf_parity_dump.rs`` (one JSON line per key:
path, last_written_raw, class_name, values[name, type, data_hex]). Every key reachable from the
root is walked with pyregf and dissect.regf and compared field by field:

- ``key_present``: our key set vs the reference key set (both directions);
- ``last_written``: raw FILETIME of each key;
- ``class_name``;
- ``value_names``, ``value_types``, ``value_data`` (multiset per key; data compared as SHA-256).

pyregf is the primary reference (``fields``); dissect.regf agreement is reported as
``fields_dissect``. Results: parity/results/regf.json (format: parity/README.md).

Known libregf-python quirks (verified against dissect.regf, which agrees with us byte for byte):
1. resident data of n < 4 bytes (stored in the vk data-offset field) is returned as the *last*
   n bytes of the little-endian 4-byte field instead of the first n, e.g. ``LangID`` field
   0x00000409 size 2 -> ``0000`` instead of ``0904``;
2. non-resident REG_SZ / REG_EXPAND_SZ data is cut after the first UTF-16 NUL, dropping slack
   bytes that are inside the declared data size.
``value_data`` is the strict byte comparison; ``value_data_libregf_normalized`` applies these
two rules to our bytes before comparing with pyregf and must agree 100%.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import subprocess
from pathlib import Path

import pytest

pyregf = pytest.importorskip("pyregf")
dissect_regf = pytest.importorskip("dissect.regf")

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "testdata" / "corpus" / "plaso"
OUT = REPO / "target" / "parity"
RESULTS = REPO / "parity" / "results" / "regf.json"

pytestmark = pytest.mark.parity

HIVES = [
    "NTUSER.DAT",
    "NTUSER-WIN7.DAT",
    "NTUSER-RunTests.DAT",
    "NTUSER-CCLEANER.DAT",
    "SYSTEM",
    "SOFTWARE",
    "regf/NTUSER.DAT",
    "regf/UsrClass.dat",
    "regf/100_sub_keys.hiv",
    "winreg/Amcache.hve",
    "winreg/win10-Amcache.hve",
]
FIELDS = ["key_present", "last_written", "class_name", "value_names", "value_types", "value_data_libregf_normalized"]

_fields: dict[str, dict[str, int]] = {}
_fields_dissect: dict[str, dict[str, int]] = {}
_samples: list[str] = []
_records = {"ours": 0, "reference": 0, "dissect": 0}
_notes: list[str] = []


def _agree(table: dict, field: str, ok: bool, n: int = 1) -> None:
    e = table.setdefault(field, {"agree": 0, "total": 0})
    e["total"] += n
    e["agree"] += n if ok else 0


def _safe(name: str) -> str:
    return name.replace("/", "__").replace("\\", "__")


def _sha(b: bytes | None) -> str | None:
    return None if b is None else hashlib.sha256(b).hexdigest()


@pytest.fixture(scope="module", autouse=True)
def dump():
    subprocess.run(
        ["cargo", "test", "-q", "--release", "-p", "veritas-artifacts", "--test", "regf_parity_dump", "--", "--ignored"],
        cwd=REPO,
        check=True,
    )
    yield
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "parser": "regf",
                "reference": f"libregf-python {pyregf.get_version()}; dissect.regf {importlib.metadata.version('dissect.regf')}",
                "samples": [f"plaso/{s}" for s in _samples],
                "records_ours": _records["ours"],
                "records_reference": _records["reference"],
                "records_dissect": _records["dissect"],
                "fields": _fields,
                "fields_dissect": _fields_dissect,
                "notes": "Keys compared by root-relative path; value data compared by SHA-256 of the raw bytes. "
                "value_data vs pyregf is below 100% only because of two libregf-python quirks (resident data "
                "< 4 bytes returned as the last n bytes of the 4-byte field; non-resident REG_SZ/REG_EXPAND_SZ cut at the first NUL, dropping in-size slack); "
                "value_data_libregf_normalized applies both and agrees 100%, and dissect.regf agrees 100% strictly. "
                + " ".join(_notes),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _libregf_view(kind: int, raw: bytes, field: str | None) -> bytes:
    """Our bytes as libregf-python would return them (see module docstring)."""
    if field is not None:
        f = bytes.fromhex(field)
        return f[4 - len(raw) :] if 0 < len(raw) < 4 else raw
    if kind in (1, 2):
        for i in range(0, len(raw) - 1, 2):
            if raw[i] == 0 and raw[i + 1] == 0:
                return raw[: i + 2]
    return raw


def _ours(name: str) -> dict[str, tuple]:
    out: dict[str, tuple] = {}
    with (OUT / "regf" / f"{_safe(name)}.jsonl").open(encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            raws = [(v["name"], v["type"], bytes.fromhex(v["data_hex"]), v.get("resident_field_hex")) for v in r["values"]]
            vals = sorted((n, t, _sha(b)) for n, t, b, _ in raws)
            norm = sorted((n, t, _sha(_libregf_view(t, b, f))) for n, t, b, f in raws)
            out[r["path"]] = (r["last_written_raw"], r["class_name"], vals, norm)
    return out


def _pyregf(name: str) -> dict[str, tuple]:
    f = pyregf.file()
    f.open(str((CORPUS / name).resolve()))
    out: dict[str, tuple] = {}
    stack = [("", f.get_root_key())]
    while stack:
        path, k = stack.pop()
        vals = []
        for v in k.values:
            try:
                data = v.data or b""
            except OSError:
                data = None
            vals.append((v.name or "", v.type, _sha(data)))
        out[path] = (k.get_last_written_time_as_integer(), k.class_name, sorted(vals, key=repr))
        for s in k.sub_keys:
            stack.append((f"{path}\\{s.name}" if path else s.name, s))
    f.close()
    return out


def _dissect(name: str) -> dict[str, tuple]:
    with (CORPUS / name).open("rb") as fh:
        hive = dissect_regf.RegistryHive(fh)
        out: dict[str, tuple] = {}
        stack = [("", hive.root())]
        while stack:
            path, k = stack.pop()
            vals = []
            for v in k.values():
                name_ = "" if v.cell.NameLength == 0 else v.name
                try:
                    data = v.data
                except Exception:  # noqa: BLE001 - reference failures are counted, not fatal
                    data = None
                vals.append((name_, v.type, _sha(data)))
            out[path] = (k.cell.LastWriteTime, k.class_name, sorted(vals, key=repr))
            for s in k.subkeys():
                stack.append((f"{path}\\{s.name}" if path else s.name, s))
    return out


def _compare(ours: dict, ref: dict, table: dict, label: str, hive: str) -> None:
    keys = set(ours) | set(ref)
    for p in keys:
        _agree(table, "key_present", p in ours and p in ref)
    for p in set(ours) & set(ref):
        lw, cls, vals, norm = ours[p]
        rlw, rcls, rvals = ref[p]
        _agree(table, "last_written", lw == rlw)
        _agree(table, "class_name", (cls or None) == (rcls or None))
        _agree(table, "value_names", sorted(v[0] for v in vals) == sorted(v[0] for v in rvals))
        _agree(table, "value_types", sorted((v[0], v[1]) for v in vals) == sorted((v[0], v[1]) for v in rvals))
        ok = sorted(vals, key=repr) == sorted(rvals, key=repr)
        _agree(table, "value_data", ok)
        if label == "pyregf":
            ok_n = sorted(norm, key=repr) == sorted(rvals, key=repr)
            _agree(table, "value_data_libregf_normalized", ok_n)
            if not ok_n and len(_notes) < 10:
                diff = sorted(set(map(repr, norm)) ^ set(map(repr, rvals)))[:2]
                _notes.append(f"[unexplained {label} {hive} {p}] {diff}")
        elif not ok and len(_notes) < 10:
            diff = sorted(set(map(repr, vals)) ^ set(map(repr, rvals)))[:2]
            _notes.append(f"[{label} {hive} {p}] {diff}")


@pytest.mark.parametrize("hive", HIVES)
def test_regf_parity(hive: str) -> None:
    if not (CORPUS / hive).exists():
        pytest.skip(f"corpus file {hive} missing")
    ours = _ours(hive)
    ref = _pyregf(hive)
    dis = _dissect(hive)
    _samples.append(hive)
    _records["ours"] += len(ours)
    _records["reference"] += len(ref)
    _records["dissect"] += len(dis)
    before = {f: dict(_fields.get(f, {"agree": 0, "total": 0})) for f in FIELDS}
    _compare(ours, ref, _fields, "pyregf", hive)
    _compare(ours, dis, _fields_dissect, "dissect", hive)
    assert set(ours) == set(ref), f"key sets differ: {sorted(set(ours) ^ set(ref))[:5]}"
    for f in FIELDS:
        agree = _fields[f]["agree"] - before[f]["agree"]
        total = _fields[f]["total"] - before[f]["total"]
        assert agree == total, f"{hive}: {f} {agree}/{total}"
    for f, v in _fields_dissect.items():
        assert v["agree"] == v["total"], f"dissect {f}: {v}"
