"""Unit tests for veritas.parsers.decrypt on the dfvfs encrypted-volume corpus.

Decrypted outputs are handed to the Rust parser (fs-tool) to prove they contain a valid file system.
Credentials are the public dfvfs test credentials.
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from veritas.parsers import decrypt

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "testdata" / "corpus" / "dfvfs"
EXPECTED_FILES = {"/a_directory", "/a_directory/a_file", "/a_directory/another_file", "/passwords.txt"}


@functools.lru_cache(maxsize=1)
def fs_tool() -> Path:
    subprocess.run(["cargo", "build", "-q", "-p", "veritas-fs", "--bin", "fs-tool"], cwd=ROOT, check=True)
    return ROOT / "target" / "debug" / ("fs-tool.exe" if os.name == "nt" else "fs-tool")


def ls(image: Path) -> list[dict]:
    out = subprocess.run([str(fs_tool()), "ls", str(image), "-r"], cwd=ROOT, check=True, capture_output=True).stdout
    return [json.loads(line) for line in out.decode("utf-8").splitlines() if line.strip()]


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def test_bitlocker_to_go_password(tmp_path):
    pytest.importorskip("pybde")
    out = tmp_path / "bde.raw"
    r = decrypt.decrypt_bitlocker(str(CORPUS / "bdetogo.raw"), str(out), password="bde-TEST")
    assert r.method == "bitlocker:password"
    assert r.size == 67108864 == out.stat().st_size
    assert r.sha256 == sha256(out)
    entries = ls(out)
    assert {e["fs_type"] for e in entries} == {"FAT16"}
    paths = {e["path"] for e in entries}
    assert EXPECTED_FILES <= paths
    assert next(e for e in entries if e["path"] == "/passwords.txt")["size"] == 116


def test_bitlocker_wrong_credentials(tmp_path):
    pytest.importorskip("pybde")
    with pytest.raises(decrypt.DecryptError):
        decrypt.decrypt_bitlocker(str(CORPUS / "bdetogo.raw"), str(tmp_path / "x.raw"), password="wrong")
    with pytest.raises(decrypt.DecryptError):
        decrypt.decrypt_bitlocker(str(CORPUS / "bdetogo.raw"), str(tmp_path / "y.raw"),
                                  recovery_password="000000-000000-000000-000000-000000-000000-000000-000000")
    with pytest.raises(decrypt.DecryptError):
        decrypt.decrypt_bitlocker(str(CORPUS / "bdetogo.raw"), str(tmp_path / "z.raw"))
    with pytest.raises(decrypt.DecryptError):
        decrypt.decrypt_bitlocker(str(CORPUS / "luks1.raw"), str(tmp_path / "n.raw"), password="bde-TEST")


def test_luks1_password(tmp_path):
    pytest.importorskip("pyluksde")
    out = tmp_path / "luks1.raw"
    r = decrypt.decrypt_luks(str(CORPUS / "luks1.raw"), str(out), password="luksde-TEST")
    assert r.method == "luks1:pyluksde"
    assert r.size == 8388608
    assert r.sha256 == sha256(out)
    entries = ls(out)
    assert {e["fs_type"] for e in entries} == {"EXT2"}
    assert EXPECTED_FILES <= {e["path"] for e in entries}


def test_luks1_wrong_password(tmp_path):
    pytest.importorskip("pyluksde")
    with pytest.raises(decrypt.DecryptError):
        decrypt.decrypt_luks(str(CORPUS / "luks1.raw"), str(tmp_path / "x.raw"), password="luks-TEST")


def test_luks2_builtin_unlock(tmp_path):
    """pyluksde cannot open this LUKS2 header; the built-in Argon2i key-slot unlock recovers the volume key.
    The corpus image ends exactly at the data segment offset (16 MiB), so the decrypted payload is empty."""
    pytest.importorskip("cryptography")
    out = tmp_path / "luks2.raw"
    r = decrypt.decrypt_luks(str(CORPUS / "luks2.raw"), str(out), password="luksde-TEST")
    assert r.method == "luks2:builtin"
    assert r.details["segment_offset"] == 16777216
    assert r.size == 0 and out.stat().st_size == 0
    key, seg = decrypt.luks2_unlock(str(CORPUS / "luks2.raw"), b"luksde-TEST")
    assert len(key) == 32 and seg["encryption"] == "aes-cbc-plain"
    with pytest.raises(decrypt.DecryptError):
        decrypt.luks2_unlock(str(CORPUS / "luks2.raw"), b"wrong")


def test_luks2_sector_cipher_roundtrip():
    """Encrypt two sectors with the reference construction and decrypt them through the adapter's cipher."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = bytes(range(32))
    plain = os.urandom(1024)
    enc = b""
    for i in range(2):
        iv = (5 + i).to_bytes(4, "little").ljust(16, b"\0")
        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        enc += e.update(plain[i * 512:(i + 1) * 512]) + e.finalize()
    assert decrypt._sector_cipher("aes-cbc-plain", key, 512)(enc, 5) == plain
    xkey = bytes(range(64))
    enc = b""
    for i in range(2):
        e = Cipher(algorithms.AES(xkey), modes.XTS((7 + i).to_bytes(16, "little"))).encryptor()
        enc += e.update(plain[i * 512:(i + 1) * 512]) + e.finalize()
    assert decrypt._sector_cipher("aes-xts-plain64", xkey, 512)(enc, 7) == plain


def test_af_merge_inverts_split():
    import hashlib as hl

    def diffuse(buf):
        out = b""
        for i in range((len(buf) + 19) // 20):
            chunk = buf[i * 20:(i + 1) * 20]
            out += hl.sha1(i.to_bytes(4, "big") + chunk).digest()[:len(chunk)]
        return out

    key = os.urandom(32)
    stripes = [os.urandom(32) for _ in range(3)]
    d = bytes(32)
    for s in stripes:
        d = diffuse(bytes(a ^ b for a, b in zip(d, s)))
    last = bytes(a ^ b for a, b in zip(d, key))
    assert decrypt._af_merge(b"".join(stripes) + last, 32, 4, "sha1") == key


def test_apfs_encrypted_unlock_matches_rust_names(tmp_path):
    pytest.importorskip("pyfsapfs")
    dmg = CORPUS / "apfs_encrypted.dmg"
    assert decrypt.find_apfs_container(str(dmg)) == (40 * 512, 8112 * 512)
    names = decrypt.list_apfs(str(dmg), password="apfs-TEST")
    # Same user-visible tree as the unencrypted apfs.raw parsed by our Rust parser (minus volume-specific
    # fseventsd log names and the resource-fork sample that only exists in apfs.raw).
    ours = {e["path"] for e in ls(CORPUS / "apfs.raw")}
    common = {"/a_directory", "/a_directory/a_file", "/a_directory/another_file", "/a_link", "/passwords.txt", "/.fseventsd", "/.fseventsd/fseventsd-uuid"}
    assert common <= set(names)
    assert common <= ours
    top = lambda s: {p for p in s if p.count("/") == 1}
    assert top(names) == top(ours)
    r = decrypt.decrypt_apfs(str(dmg), str(tmp_path / "apfs"), password="apfs-TEST")
    assert r.method == "apfs:pyfsapfs"
    assert (tmp_path / "apfs" / "a_directory" / "a_file").read_bytes() == b"This is a text file.\n\nWe should be able to parse it.\n"
    manifest = (tmp_path / "apfs" / "manifest.jsonl").read_bytes()
    assert hashlib.sha256(manifest).hexdigest() == r.sha256
    assert [json.loads(line)["path"] for line in manifest.splitlines()] == names
    # Deterministic: a second extraction yields the same manifest hash.
    r2 = decrypt.decrypt_apfs(str(dmg), str(tmp_path / "apfs2"), password="apfs-TEST")
    assert r2.sha256 == r.sha256


def test_apfs_wrong_password(tmp_path):
    pytest.importorskip("pyfsapfs")
    with pytest.raises(decrypt.DecryptError):
        decrypt.list_apfs(str(CORPUS / "apfs_encrypted.dmg"), password="nope")
    with pytest.raises(decrypt.DecryptError):
        decrypt.find_apfs_container(str(CORPUS / "ntfs.raw"))
