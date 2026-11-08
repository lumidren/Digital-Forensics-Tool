"""Parity: veritas-aff4 (Rust) against pyaff4 in both directions.

1. Containers written by `aff4-tool write` are opened with pyaff4 (``Container.openURNtoContainer``,
   which resolves aff4:Image -> aff4:dataStream -> aff4:Map -> aff4:ImageStream); media size,
   the stored MD5 / SHA-1 (aff4:hash literals) against the source, compression method, chunk
   size and every media byte must agree.
2. Containers written with pyaff4's own API in this test (ZIP volume, AFF4 v1.0 ImageStream with
   bevies and indexes, aff4:Map, aff4:Image with hashes) are read by `aff4-tool info/verify/dump`;
   media size, stored hashes, verification and every media byte must agree with the source and
   with pyaff4's own reading.

Results are written to parity/results/aff4.json (format: parity/README.md).
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")
pyaff4 = pytest.importorskip("pyaff4")

from pyaff4 import aff4_image, aff4_map, container, data_store, hashes, lexicon, rdfvalue  # noqa: E402
from pyaff4 import zip as aff4_zip  # noqa: E402
from pyaff4.version import Version  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "testdata" / "corpus"
RESULTS = REPO / "parity" / "results" / "aff4.json"
EXE = REPO / "target" / "debug" / ("aff4-tool.exe" if os.name == "nt" else "aff4-tool")

pytestmark = pytest.mark.parity

_fields: dict[str, dict[str, int]] = {}
_samples: list[str] = []
_records = {"ours": 0, "reference": 0}


def _agree(field: str, ok: bool) -> None:
    entry = _fields.setdefault(field, {"agree": 0, "total": 0})
    entry["total"] += 1
    entry["agree"] += 1 if ok else 0


def _pyaff4_version() -> str:
    try:
        from importlib.metadata import version

        return version("pyaff4")
    except Exception:  # pragma: no cover
        return "unknown"


@pytest.fixture(scope="module", autouse=True)
def tool():
    subprocess.run(["cargo", "build", "-q", "-p", "veritas-aff4", "--bin", "aff4-tool"], cwd=REPO, check=True)
    assert EXE.is_file(), EXE
    yield EXE
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "parser": "aff4",
                "reference": f"pyaff4 {_pyaff4_version()}",
                "samples": _samples,
                "records_ours": _records["ours"],
                "records_reference": _records["reference"],
                "fields": _fields,
                "notes": (
                    "Direction 1: AFF4 Standard v1.0 containers written by veritas-aff4 (ImageStream behind a "
                    "linear aff4:Map, deflate/zlib, snappy and stored chunks) opened with pyaff4. Direction 2: "
                    "containers written with pyaff4's API (zlib, snappy and stored ImageStreams, aff4:Map, "
                    "aff4:Image with MD5/SHA-1 aff4:hash literals) read by veritas-aff4. raw-deflate (RFC 1951, "
                    "Evimetry) is not compared because pyaff4 cannot read it; LZ4 is read-only in veritas-aff4 "
                    "and pyaff4's LZ4 writer prefixes a size header that the AFF4 convention does not use. "
                    "pyaff4 0.34 was installed without its exact pins (rdflib 7, pycryptodome 3, python-snappy)."
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


def _random_input(tmp: Path, size: int, seed: int) -> Path:
    rng = random.Random(seed)
    data = bytearray()
    while len(data) < size:
        data += bytes(4096) if rng.random() < 0.3 else rng.randbytes(4096)
    p = tmp / f"random{seed}.bin"
    p.write_bytes(bytes(data[:size]))
    return p


def _source(tmp: Path, name: str) -> Path:
    if name == "random":
        return _random_input(tmp, 3 * 1024 * 1024 + 1234, 1234)  # not a multiple of the chunk size
    if name == "tiny":
        return _random_input(tmp, 100, 7)
    return CORPUS / name


def _open_pyaff4(path: Path):
    c = container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(str(path.resolve())))
    stream = c.image.dataStream
    stored = {}
    for h in c.resolver.QuerySubjectPredicate(c.urn, c.image.urn, lexicon.standard.hash):
        stored[str(h.datatype).rsplit("#", 1)[-1].lower()] = str(h).lower()
    return c, stream, stored


def _read_all(stream) -> bytes:
    size = stream.Size()
    stream.SeekRead(0)
    out = bytearray()
    while len(out) < size:
        piece = stream.Read(min(4 * 1024 * 1024, size - len(out)))
        if not piece:
            break
        out += piece
    return bytes(out)


WRITE_CASES = [
    ("dfvfs/ntfs.raw", "deflate", 2048),
    ("dfvfs/ext2.raw", "snappy", 16),
    ("dfvfs/fat12.raw", "stored", 64),
    ("random", "deflate", 8),
    ("tiny", "snappy", 2048),
]


@pytest.mark.parametrize("source,compression,cis", WRITE_CASES)
def test_ours_written_pyaff4_reads(tmp_path, source, compression, cis):
    src = _source(tmp_path, source)
    out = tmp_path / "out.aff4"
    summary = _run("write", str(src), str(out), "--compression", compression, "--chunks-per-segment", str(cis),
                   "--case", "CASE-2026-001", "--examiner", "Parity Examiner")
    _samples.append(f"ours:{source}:{compression}:cis={cis}")
    _records["ours"] += 1
    _records["reference"] += 1
    raw = src.read_bytes()
    c, stream, stored = _open_pyaff4(out)
    target = c.resolver.AFF4FactoryOpen(rdfvalue.URN(summary["stream_urn"]))
    try:
        size_ok = stream.Size() == len(raw) == summary["media_size"]
        _agree("media_size", size_ok)
        md5_ok = stored.get("md5") == hashlib.md5(raw).hexdigest() == summary["hashes"]["md5"]
        _agree("md5", md5_ok)
        sha1_ok = stored.get("sha1") == hashlib.sha1(raw).hexdigest() == summary["sha1"]
        _agree("sha1", sha1_ok)
        sha256_ok = stored.get("sha256") == hashlib.sha256(raw).hexdigest()
        _agree("sha256", sha256_ok)
        method_ok = str(target.compression) == summary["compression_uri"]
        _agree("compression_method", method_ok)
        chunk_ok = target.chunk_size == summary["chunk_size"] and target.chunks_per_segment == cis
        _agree("chunk_layout", chunk_ok)
        bytes_ok = _read_all(stream) == raw
        _agree("media_bytes", bytes_ok)
    finally:
        c.resolver.Return(target)
    assert size_ok and md5_ok and sha1_ok and sha256_ok and method_ok and chunk_ok and bytes_ok, (stored, summary)


def _pyaff4_write(path: Path, raw: bytes, compression: str, chunk_size: int, cis: int) -> None:
    urn = rdfvalue.URN.FromFileName(str(path.resolve()))
    with data_store.MemoryDataStore() as resolver:
        resolver.Set(lexicon.transient_graph, urn, lexicon.AFF4_STREAM_WRITE_MODE, rdfvalue.XSDString("truncate"))
        version = Version(1, 0, "pyaff4")
        with aff4_zip.ZipFile.NewZipFile(resolver, version, urn) as zf:
            volume = zf.urn
            with zf.CreateMember(volume.Append("container.description")) as f:
                f.Write(str(volume).encode())
            with zf.CreateMember(volume.Append("version.txt")) as f:
                f.Write(str(version).encode())
            image_urn = rdfvalue.URN("aff4://%s" % hashlib.md5(raw[:4096] + compression.encode()).hexdigest())
            stream_urn = image_urn.Append("stream")
            map_urn = image_urn.Append("map")
            with aff4_image.AFF4Image.NewAFF4Image(resolver, stream_urn, volume) as stream:
                stream.chunk_size = chunk_size
                stream.chunks_per_segment = cis
                stream.setCompressionMethod({
                    "zlib": lexicon.AFF4_IMAGE_COMPRESSION_ZLIB,
                    "snappy": lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY,
                    "stored": lexicon.AFF4_IMAGE_COMPRESSION_STORED,
                }[compression])
                for i in range(0, len(raw), 1 << 20):
                    stream.Write(raw[i:i + (1 << 20)])
            with aff4_map.AFF4Map.NewAFF4Map(resolver, map_urn, volume) as m:
                m.AddRange(0, 0, len(raw), stream_urn)
            resolver.Add(volume, image_urn, lexicon.AFF4_TYPE, rdfvalue.URN(lexicon.standard.Image))
            resolver.Add(volume, image_urn, lexicon.AFF4_TYPE, rdfvalue.URN(lexicon.AFF4_NAMESPACE + "DiskImage"))
            resolver.Add(volume, image_urn, lexicon.standard.dataStream, map_urn)
            resolver.Add(volume, image_urn, lexicon.standard.hash, hashes.newImmutableHash(hashlib.md5(raw).hexdigest(), lexicon.HASH_MD5))
            resolver.Add(volume, image_urn, lexicon.standard.hash, hashes.newImmutableHash(hashlib.sha1(raw).hexdigest(), lexicon.HASH_SHA1))


READ_CASES = [
    ("dfvfs/ntfs.raw", "zlib", 32768, 1024),
    ("dfvfs/ext2.raw", "snappy", 32768, 8),
    ("random", "stored", 32768, 16),
    ("random", "zlib", 65536, 3),
    ("tiny", "zlib", 32768, 1024),
]


@pytest.mark.parametrize("source,compression,chunk_size,cis", READ_CASES)
def test_pyaff4_written_read_by_ours(tmp_path, source, compression, chunk_size, cis):
    src = _source(tmp_path, source)
    raw = src.read_bytes()
    img = tmp_path / "ref.aff4"
    _pyaff4_write(img, raw, compression, chunk_size, cis)
    _samples.append(f"reference:pyaff4:{source}:{compression}:chunk={chunk_size}:cis={cis}")
    _records["ours"] += 1
    _records["reference"] += 1

    info = _run("info", str(img))
    verify = _run("verify", str(img))
    dump_path = tmp_path / "media.raw"
    _run("dump", str(img), str(dump_path))
    c, stream, stored = _open_pyaff4(img)
    reference = _read_all(stream)
    ref_size = stream.Size()
    del c, stream
    ours_stored = {h["algorithm"]: h["value"] for h in info["stored_hashes"]}

    size_ok = info["media_size"] == ref_size == len(raw)
    _agree("media_size", size_ok)
    md5_ok = ours_stored.get("md5") == stored.get("md5") == hashlib.md5(raw).hexdigest() and verify["md5_match"] is True
    _agree("md5", md5_ok)
    sha1_ok = ours_stored.get("sha1") == stored.get("sha1") == hashlib.sha1(raw).hexdigest() and verify["sha1_match"] is True
    _agree("sha1", sha1_ok)
    verified_ok = verify["verified"] is True and not verify["crc_errors"]
    _agree("verify", verified_ok)
    stream_info = info["streams"][0] if info["streams"] else {}
    layout_ok = (
        info["layout"] == "map"
        and stream_info.get("chunk_size") == chunk_size
        and stream_info.get("chunks_per_segment") == cis
    )
    _agree("chunk_layout", layout_ok)
    bytes_ok = dump_path.read_bytes() == reference == raw
    _agree("media_bytes", bytes_ok)
    assert size_ok and md5_ok and sha1_ok and verified_ok and layout_ok and bytes_ok, (info, verify)
