"""Parity: veritas-ewf (Rust) against libewf (pyewf) in both directions.

1. Images written by `ewf-tool write` are opened with pyewf; media size, stored MD5/SHA-1, header
   values and every media byte must agree with the source.
2. Reference images from the public corpus are read by `ewf-tool info/dump`; media size, stored
   MD5, header values and every media byte must agree with pyewf.

Results are written to parity/results/ewf.json (format: parity/README.md).
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
from pathlib import Path

import pytest

pyewf = pytest.importorskip("pyewf")

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "testdata" / "corpus"
RESULTS = REPO / "parity" / "results" / "ewf.json"
EXE = REPO / "target" / "debug" / ("ewf-tool.exe" if os.name == "nt" else "ewf-tool")

pytestmark = pytest.mark.parity

HEADER_FIELDS = {
    "case_number": "case_number",
    "evidence_number": "evidence_number",
    "examiner_name": "examiner_name",
    "notes": "notes",
    "description": "description",
}

_fields: dict[str, dict[str, int]] = {}
_samples: list[str] = []
_records = {"ours": 0, "reference": 0}


def _agree(field: str, ok: bool) -> None:
    entry = _fields.setdefault(field, {"agree": 0, "total": 0})
    entry["total"] += 1
    entry["agree"] += 1 if ok else 0


@pytest.fixture(scope="module", autouse=True)
def tool():
    subprocess.run(
        ["cargo", "build", "-q", "-p", "veritas-ewf", "--bin", "ewf-tool"], cwd=REPO, check=True
    )
    assert EXE.is_file(), EXE
    yield EXE
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "parser": "ewf",
                "reference": f"libewf (pyewf) {pyewf.get_version()}",
                "samples": _samples,
                "records_ours": _records["ours"],
                "records_reference": _records["reference"],
                "fields": _fields,
                "notes": (
                    "Direction 1: images written by veritas-ewf opened with pyewf. "
                    "Direction 2: corpus images written by EnCase/ewfacquire read by veritas-ewf. "
                    "Inputs that are not a multiple of 512 bytes are zero-padded to the sector "
                    "boundary by the writer, as EWF stores whole sectors; comparisons use the padded media."
                ),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _run(*args: str) -> dict:
    out = subprocess.run([str(EXE), *args], capture_output=True, text=True, check=False)
    assert out.returncode in (0, 1), out.stderr
    return json.loads(out.stdout)


def _pyewf_open(first: Path):
    handle = pyewf.handle()
    handle.open(pyewf.glob(str(first.resolve())))
    return handle


def _pyewf_bytes(handle) -> bytes:
    size = handle.get_media_size()
    chunks = []
    offset = 0
    while offset < size:
        n = min(4 * 1024 * 1024, size - offset)
        chunks.append(handle.read_buffer_at_offset(n, offset))
        offset += n
    return b"".join(chunks)


def _random_input(tmp: Path) -> Path:
    rng = random.Random(1234)
    data = bytearray()
    for i in range(48):
        block = bytes(4096) if i % 3 == 0 else rng.randbytes(32768)
        data += block
    data += rng.randbytes(100)  # not a multiple of the sector size
    p = tmp / "random.bin"
    p.write_bytes(bytes(data))
    return p


WRITE_CASES = [
    ("dfvfs/ext2.raw", "fast", None),
    ("dfvfs/ext2.raw", "none", 1024 * 1024),
    ("dfvfs/ntfs.raw", "best", 256 * 1024),
    ("random", "fast", 512 * 1024),
]


@pytest.mark.parametrize("source,compression,segment_size", WRITE_CASES)
def test_ours_written_pyewf_reads(tmp_path, source, compression, segment_size):
    src = _random_input(tmp_path) if source == "random" else CORPUS / source
    meta = {
        "case": "CASE-2026-001",
        "evidence": "EV-17",
        "examiner": "Parity Examiner",
        "description": f"parity {source}",
        "notes": "written by veritas-ewf",
    }
    args = ["write", str(src), str(tmp_path / "out"), "--compression", compression]
    for k, v in meta.items():
        args += [f"--{k}", v]
    if segment_size:
        args += ["--segment-size", str(segment_size)]
    summary = _run(*args)
    _samples.append(f"ours:{source}:{compression}:{segment_size or 'default'}")
    _records["ours"] += 1
    _records["reference"] += 1

    raw = src.read_bytes()
    padded = raw + bytes((-len(raw)) % 512)
    handle = _pyewf_open(tmp_path / "out.E01")
    try:
        assert len(pyewf.glob(str((tmp_path / "out.E01").resolve()))) == len(summary["segments"])
        size_ok = handle.get_media_size() == len(padded) == summary["media_size"]
        _agree("media_size", size_ok)
        md5_ok = handle.get_hash_value("MD5") == hashlib.md5(padded).hexdigest() == summary["hashes"]["md5"]
        _agree("md5", md5_ok)
        sha1_ok = handle.get_hash_value("SHA1") == hashlib.sha1(padded).hexdigest() == summary["sha1"]
        _agree("sha1", sha1_ok)
        values = handle.get_header_values()
        expected = {
            "case_number": meta["case"],
            "evidence_number": meta["evidence"],
            "examiner_name": meta["examiner"],
            "notes": meta["notes"],
            "description": meta["description"],
        }
        header_ok = all(values.get(k) == v for k, v in expected.items())
        _agree("header_values", header_ok)
        date_ok = bool(values.get("acquiry_date"))
        _agree("acquiry_date_present", date_ok)
        bytes_ok = _pyewf_bytes(handle) == padded
        _agree("media_bytes", bytes_ok)
    finally:
        handle.close()
    assert size_ok and md5_ok and sha1_ok and header_ok and date_ok and bytes_ok, values


READ_CASES = ["dfvfs/ext2.E01", "dfvfs/ext2.split.E01", "plaso/image.E01", "plaso/image-split.E01"]


@pytest.mark.parametrize("name", READ_CASES)
def test_reference_images_read_by_ours(tmp_path, name):
    first = CORPUS / name
    _samples.append(f"reference:{name}")
    _records["ours"] += 1
    _records["reference"] += 1
    info = _run("info", str(first))
    verify = _run("verify", str(first))
    dump_path = tmp_path / "media.raw"
    _run("dump", str(first), str(dump_path))

    handle = _pyewf_open(first)
    try:
        size_ok = info["media_size"] == handle.get_media_size()
        _agree("media_size", size_ok)
        md5_ok = info["stored_md5"] == handle.get_hash_value("MD5") and verify["verified"]
        _agree("md5", md5_ok)
        values = handle.get_header_values()
        header_ok = all(info["header"][ours] == values.get(ref, "") for ref, ours in HEADER_FIELDS.items())
        _agree("header_values", header_ok)
        date_ok = (info["header"]["acquiry_date"] is not None) == bool(values.get("acquiry_date"))
        _agree("acquiry_date_present", date_ok)
        bytes_ok = dump_path.read_bytes() == _pyewf_bytes(handle)
        _agree("media_bytes", bytes_ok)
        segs_ok = len(info["segments"]) == len(pyewf.glob(str(first.resolve())))
        _agree("segment_count", segs_ok)
    finally:
        handle.close()
    assert size_ok and md5_ok and header_ok and date_ok and bytes_ok and segs_ok, info["header"]
