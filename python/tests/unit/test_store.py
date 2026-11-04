import io
import os
import stat

import pytest

from veritas.store.content import CaseKeyring, CorruptObject, FRAME_SIZE, LocalStore, S3Store, StoreError, hash_file


def test_plain_roundtrip_worm(tmp_path):
    s = LocalStore(tmp_path)
    m = s.put("C1", io.BytesIO(b"hello"), "h.txt")
    assert m.hashes.md5 == "5d41402abc4b2a76b9719d911017c592" and m.hashes.length == 5
    assert s.open(m.address).read() == b"hello"
    assert not os.stat(s._obj(m.address)).st_mode & stat.S_IWRITE
    again = s.put("C2", io.BytesIO(b"hello"))
    assert again.case_id == "C1" and s.list() == [m.address]
    assert s.verify(m.address) and s.exists(m.address) and not s.exists("x")
    with pytest.raises(StoreError):
        s.meta("0" * 64)


def test_encrypted_roundtrip_isolation_and_tamper(tmp_path):
    ring = CaseKeyring(bytes(range(32)))
    s = LocalStore(tmp_path, ring)
    data = os.urandom(2 * FRAME_SIZE + 77)
    m = s.put("CASE-A", io.BytesIO(data))
    assert m.encrypted and s.open(m.address).read() == data and s.verify(m.address)
    raw = s._obj(m.address).read_bytes()
    assert data[:64] not in raw
    assert ring.case_key("A") != ring.case_key("B")
    # Wrong case key cannot decrypt.
    other = LocalStore(tmp_path, CaseKeyring(bytes(32)))
    with pytest.raises(CorruptObject):
        other.open(m.address).read()
    # Flip one ciphertext byte: verify fails rather than returning altered plaintext.
    p = s._obj(m.address)
    os.chmod(p, stat.S_IREAD | stat.S_IWRITE)
    b = bytearray(raw)
    b[100] ^= 1
    p.write_bytes(bytes(b))
    assert not s.verify(m.address)
    mat = tmp_path / "mat"
    mat.mkdir()
    s2 = LocalStore(tmp_path / "s2", ring)
    m2 = s2.put("CASE-A", io.BytesIO(b"abc"))
    assert s2.materialize(m2.address, mat).read_bytes() == b"abc"
    assert hash_file(mat / m2.address).sha256 == m2.address


def test_s3_requires_object_lock():
    class FakeS3:
        def get_object_lock_configuration(self, Bucket):
            return {"ObjectLockConfiguration": {}}

    pytest.importorskip("boto3")
    with pytest.raises(StoreError):
        S3Store("b", client=FakeS3())


def test_keyring_from_env(monkeypatch):
    monkeypatch.setenv("VERITAS_MASTER_KEY", "11" * 32)
    assert CaseKeyring.from_env() is not None
    monkeypatch.delenv("VERITAS_MASTER_KEY")
    assert CaseKeyring.from_env() is None
    with pytest.raises(ValueError):
        CaseKeyring(b"short")
