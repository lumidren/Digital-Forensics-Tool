"""AFF4 containers are ZIP files, but they are disk images: classify() must say "disk"."""
import io
import struct
import zipfile

from veritas.pipeline.queue import classify, is_aff4


def _zip(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


def _zip64_local(name: str, data: bytes) -> bytes:
    """A local header as veritas-aff4 writes it: sizes in a ZIP64 extra field."""
    n = name.encode()
    extra = struct.pack("<HHQQ", 1, 16, len(data), len(data))
    hdr = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 45, 0x800, 0, 0, 0x21, 0, 0xFFFFFFFF, 0xFFFFFFFF, len(n), len(extra))
    return hdr + n + extra + data


def test_pyaff4_style_container_is_disk():
    head = _zip([
        ("container.description", b"aff4://0a1b"),
        ("version.txt", b"major=1\nminor=0\ntool=pyaff4\n"),
        ("aff4%3A%2F%2F0a1b/00000000", bytes(65536)),
        ("information.turtle", b"@prefix aff4: <http://aff4.org/Schema#> ."),
    ])[:4096]
    assert is_aff4(head)
    assert classify(head, None, "evidence.bin") == "disk"
    # Declared as a triage bundle, it is still a disk image.
    assert classify(head, "triage", "evidence.zip") == "disk"


def test_bevy_first_container_is_disk():
    # Evimetry-style ordering: a stream member comes first.
    head = _zip([("aff4%3A%2F%2Ffcbf/00000000", bytes(100000)), ("information.turtle", b"x")])[:4096]
    assert classify(head, None, "image") == "disk"


def test_veritas_zip64_local_headers_are_walked():
    head = (_zip64_local("readme", b"x" * 100) + _zip64_local("information.turtle", b"@prefix"))[:4096]
    assert is_aff4(head)
    assert classify(head, None, "") == "disk"


def test_aff4_name_with_unknown_first_member():
    head = _zip([("blob", bytes(100000))])[:4096]
    assert classify(head, None, "image.AFF4") == "disk"
    assert classify(head, None, "image.zip") == "auto"


def test_plain_zip_is_not_aff4():
    head = _zip([("Windows/System32/config/SYSTEM", b"regf"), ("manifest.json", b"{}")])[:4096]
    assert not is_aff4(head)
    assert classify(head, None, "bundle.zip") == "auto"
    assert classify(head, "triage", "bundle.zip") == "triage"
    assert not is_aff4(b"PK\x03\x04")
    assert not is_aff4(b"")
