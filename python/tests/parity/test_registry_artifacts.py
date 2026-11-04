"""Parity: registry artifact plugins (Rust) against small independent Python decoders.

No installed reference library decodes AppCompatCache or UserAssist (dissect.regf is a hive
reader only; python-registry / regipy are not dependencies), so this test carries its own
minimal decoders written from the public format descriptions, and reads the raw value bytes
with libregf (pyregf), not with our parser:

- AppCompatCache: Mandiant, "Leveraging the Application Compatibility Cache in Forensic
  Investigations" (2012) layouts for XP, 2003/Vista, Win7 (32/64-bit), Win8.x (``00ts`` /
  ``10ts``) and Win10 (header 0x30 / 0x34). Additionally the first and last five entries of the
  corpus SYSTEM hive are checked against a hand decode (``HAND_CHECK`` below).
- UserAssist: ROT13 of the value name; XP 16-byte (count - 5, FILETIME @8) and Win7 72-byte
  (count @4, focus count @8, focus ms @12, FILETIME @60) layouts.

Our side comes from ``crates/veritas-artifacts/tests/regf_parity_dump.rs``.
Results: parity/results/registry_artifacts.json.
"""

from __future__ import annotations

import codecs
import json
import struct
import subprocess
from pathlib import Path

import pytest

pyregf = pytest.importorskip("pyregf")

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "testdata" / "corpus" / "plaso"
OUT = REPO / "target" / "parity" / "registry"
RESULTS = REPO / "parity" / "results" / "registry_artifacts.json"

pytestmark = pytest.mark.parity

# Hand decode of SYSTEM ControlSet001\Control\Session Manager\AppCompatCache (Win7 32-bit,
# 330 entries): (index, path, last-modified FILETIME, insert flags).
HAND_CHECK = [
    (0, "\\??\\C:\\Program Files\\McAfee\\VirusScan Enterprise\\mfeann.exe", 129393076800000000, 7),
    (1, "\\??\\C:\\Windows\\servicing\\TrustedInstaller.exe", 129347290681480000, 7),
    (2, "\\??\\C:\\Windows\\system32\\LogonUI.exe", 129347290363270000, 7),
    (3, "\\??\\C:\\Windows\\system32\\reg.exe", 128920076703640000, 7),
    (4, "\\??\\C:\\Windows\\system32\\cmd.exe", 129347290204010000, 7),
    (325, "\\??\\C:\\Windows\\WinSxS\\x86_microsoft-windows-p..g-xpsdocumentwriter_31bf3856ad364e35_6.1.7601.17514_none_24e008d5c14862bc\\MxdwGc.exe", 129347290459670000, 7),
    (326, "\\??\\C:\\Windows\\System32\\netcfg.exe", 129347290461700000, 7),
    (327, "\\??\\C:\\Windows\\System32\\netsh.exe", 128920076675560000, 7),
    (328, "\\??\\C:\\Windows\\WinSxS\\x86_microsoft-windows-eudc-settings_31bf3856ad364e35_6.1.7601.17514_none_5c2f2db5367a1410\\eudcsettings.exe", 129347290286840000, 7),
    (329, "\\??\\C:\\Windows\\bfsvc.exe", 129347290158000000, 7),
]

_fields: dict[str, dict[str, int]] = {}
_samples: list[str] = []
_records = {"ours": 0, "reference": 0}


def _agree(field: str, ok: bool) -> None:
    e = _fields.setdefault(field, {"agree": 0, "total": 0})
    e["total"] += 1
    e["agree"] += 1 if ok else 0


def _safe(name: str) -> str:
    return name.replace("/", "__").replace("\\", "__")


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
                "parser": "registry_artifacts",
                "reference": f"independent Python decoders over libregf-python {pyregf.get_version()} raw values",
                "samples": [f"plaso/{s}" for s in _samples],
                "records_ours": _records["ours"],
                "records_reference": _records["reference"],
                "fields": _fields,
                "notes": "shimcache: Mandiant format description, plus hand check of first/last 5 SYSTEM entries; "
                "userassist: ROT13 + XP/Win7 layouts.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _open(name: str):
    f = pyregf.file()
    f.open(str((CORPUS / name).resolve()))
    return f


def _ours(name: str) -> dict:
    return json.loads((OUT / f"{_safe(name)}.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------------------------
# Independent AppCompatCache decoder
# ---------------------------------------------------------------------------------------------


def _u16(s: bytes) -> str:
    return s.decode("utf-16-le", "replace").split("\x00")[0]


def decode_shimcache(d: bytes) -> tuple[str, list[tuple[str, int, int | None]]]:
    """Return (format, [(path, mtime, insert_flags_or_None)])."""
    sig = struct.unpack_from("<I", d, 0)[0]
    out: list[tuple[str, int, int | None]] = []
    if sig == 0xDEADBEEF:
        n = struct.unpack_from("<I", d, 4)[0]
        for i in range(n):
            o = 400 + i * 552
            out.append((_u16(d[o : o + 520]), struct.unpack_from("<Q", d, o + 528)[0], None))
        return "winxp_32", out
    if sig in (0xBADC0FFE, 0xBADC0FEE):
        n = struct.unpack_from("<I", d, 4)[0]
        hdr = 8 if sig == 0xBADC0FFE else 128
        is64 = n > 0 and struct.unpack_from("<I", d, hdr + 4)[0] == 0
        for i in range(n):
            if sig == 0xBADC0FEE and is64:
                ln, _mx, _pad, poff, mt, fl = struct.unpack_from("<HHIQQI", d, hdr + i * 48)
            elif sig == 0xBADC0FEE:
                ln, _mx, poff, mt, fl = struct.unpack_from("<HHIQI", d, hdr + i * 32)
            elif is64:
                ln, _mx, _pad, poff, mt = struct.unpack_from("<HHIQQ", d, hdr + i * 32)
                fl = None
            else:
                ln, _mx, poff, mt = struct.unpack_from("<HHIQ", d, hdr + i * 24)
                fl = None
            out.append((_u16(d[poff : poff + ln]), mt, fl))
        fmt = ("win7" if sig == 0xBADC0FEE else "win2003_vista") + ("_64" if is64 else "_32")
        return fmt, out
    if sig == 0x80 and d[128:132] in (b"00ts", b"10ts"):
        win81 = d[128:132] == b"10ts"
        o = 128
        while d[o : o + 4] in (b"00ts", b"10ts"):
            size = struct.unpack_from("<I", d, o + 8)[0]
            e = d[o + 12 : o + 12 + size]
            pl = struct.unpack_from("<H", e, 0)[0]
            path = _u16(e[2 : 2 + pl])
            p = 2 + pl
            if win81:
                p += 2 + struct.unpack_from("<H", e, p)[0]
            fl, _sf, mt = struct.unpack_from("<IIQ", e, p)
            out.append((path, mt, fl))
            o += 12 + size
        return ("win8.1" if win81 else "win8.0"), out
    if sig in (0x30, 0x34):
        o = sig
        while d[o : o + 4] == b"10ts":
            size = struct.unpack_from("<I", d, o + 8)[0]
            e = d[o + 12 : o + 12 + size]
            pl = struct.unpack_from("<H", e, 0)[0]
            out.append((_u16(e[2 : 2 + pl]), struct.unpack_from("<Q", e, 2 + pl)[0], None))
            o += 12 + size
        return ("win10" if sig == 0x30 else "win10_creators"), out
    raise ValueError(f"unknown signature {sig:#x}")


def test_shimcache_system() -> None:
    name = "SYSTEM"
    if not (CORPUS / name).exists():
        pytest.skip("SYSTEM missing")
    f = _open(name)
    cur = struct.unpack("<I", f.get_key_by_path("Select").get_value_by_name("Current").data)[0]
    k = f.get_key_by_path(f"ControlSet{cur:03d}\\Control\\Session Manager\\AppCompatCache")
    raw = k.get_value_by_name("AppCompatCache").data
    f.close()
    fmt, ref = decode_shimcache(raw)
    ours = _ours(name)["shimcache"]
    _samples.append(f"{name}#AppCompatCache")
    _records["ours"] += len(ours["entries"])
    _records["reference"] += len(ref)
    _agree("shimcache_format", ours["format"] == fmt)
    _agree("shimcache_count", len(ours["entries"]) == len(ref))
    for e, (path, mt, fl) in zip(ours["entries"], ref):
        _agree("shimcache_path", e["path"] == path)
        _agree("shimcache_last_modified", e["last_modified_raw"] == mt)
        _agree("shimcache_executed", e["executed"] == (None if fl is None else bool(fl & 2)))
    for idx, path, mt, fl in HAND_CHECK:
        e = ours["entries"][idx]
        _agree("shimcache_hand_check", (e["index"], e["path"], e["last_modified_raw"], e["insert_flags"]) == (idx, path, mt, fl))
    assert fmt == "win7_32" and len(ref) == 330
    for k_, v in _fields.items():
        if k_.startswith("shimcache"):
            assert v["agree"] == v["total"], (k_, v)


# ---------------------------------------------------------------------------------------------
# Independent UserAssist decoder
# ---------------------------------------------------------------------------------------------


def decode_userassist(name: str) -> list[dict]:
    f = _open(name)
    k = f.get_key_by_path("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    out = []
    for g in k.sub_keys:
        c = g.get_sub_key_by_name("Count")
        if c is None:
            continue
        for v in c.values:
            d = v.data or b""
            vn = codecs.decode(v.name or "", "rot13")
            if len(d) == 16:
                cnt = struct.unpack_from("<I", d, 4)[0]
                cnt = cnt - 5 if cnt > 5 else cnt
                out.append({"guid": g.name, "value_name": vn, "count": cnt, "focus_count": None, "focus_duration_ms": None,
                            "last_executed_raw": struct.unpack_from("<Q", d, 8)[0], "format": "xp"})
            elif len(d) == 72:
                cnt, fc, fd = struct.unpack_from("<III", d, 4)
                out.append({"guid": g.name, "value_name": vn, "count": cnt, "focus_count": fc, "focus_duration_ms": fd,
                            "last_executed_raw": struct.unpack_from("<Q", d, 60)[0], "format": "win7"})
    f.close()
    return out


@pytest.mark.parametrize("name", ["NTUSER.DAT", "NTUSER-WIN7.DAT", "NTUSER-CCLEANER.DAT", "regf/NTUSER.DAT"])
def test_userassist(name: str) -> None:
    if not (CORPUS / name).exists():
        pytest.skip(f"{name} missing")
    ref = decode_userassist(name)
    ours = _ours(name)["userassist"]
    _samples.append(f"{name}#UserAssist")
    _records["ours"] += len(ours)
    _records["reference"] += len(ref)
    _agree("userassist_count_entries", len(ours) == len(ref))
    key = lambda e: (e["guid"], e["value_name"])  # noqa: E731
    rmap = {key(e): e for e in ref}
    for e in ours:
        r = rmap.get(key(e))
        _agree("userassist_value_name", r is not None)
        if r is None:
            continue
        for fld in ("count", "focus_count", "focus_duration_ms", "last_executed_raw", "format"):
            _agree(f"userassist_{fld}", e[fld] == r[fld])
    assert len(ours) == len(ref)
    for k_, v in _fields.items():
        if k_.startswith("userassist"):
            assert v["agree"] == v["total"], (k_, v)
