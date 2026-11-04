"""Minimal, bounds-checked TLS handshake decoding: ClientHello (SNI, ALPN, JA3), ServerHello (JA3S)
and the server Certificate chain (subject, issuer, validity, fingerprint).

Only the cleartext handshake is examined; TLS 1.3 certificates are encrypted and therefore absent.
Every parser takes a byte string and returns ``None``/partial results instead of raising.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any

HANDSHAKE = 22
CHANGE_CIPHER_SPEC = 20
APPLICATION_DATA = 23
MAX_HANDSHAKE_BYTES = 256 * 1024


def is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def looks_like_tls(buf: bytes) -> bool:
    return len(buf) >= 3 and buf[0] == HANDSHAKE and buf[1] == 3 and buf[2] <= 4


def handshake_bytes(stream: bytes) -> bytes:
    """Concatenate handshake-record payloads from the start of a stream until encryption starts."""
    out = bytearray()
    pos = 0
    while pos + 5 <= len(stream) and len(out) < MAX_HANDSHAKE_BYTES:
        ctype, _ver, length = stream[pos], stream[pos + 1:pos + 3], struct.unpack(">H", stream[pos + 3:pos + 5])[0]
        if ctype not in (HANDSHAKE, CHANGE_CIPHER_SPEC, 21, APPLICATION_DATA) or _ver[0] != 3:
            break
        if ctype in (CHANGE_CIPHER_SPEC, APPLICATION_DATA):
            break
        if ctype == HANDSHAKE:
            out += stream[pos + 5:pos + 5 + length]
        pos += 5 + length
    return bytes(out)


def iter_handshakes(hs: bytes):
    pos = 0
    while pos + 4 <= len(hs):
        htype = hs[pos]
        hlen = int.from_bytes(hs[pos + 1:pos + 4], "big")
        body = hs[pos + 4:pos + 4 + hlen]
        if len(body) < hlen:
            yield htype, body, False
            return
        yield htype, body, True
        pos += 4 + hlen


class _Reader:
    __slots__ = ("b", "p")

    def __init__(self, b: bytes) -> None:
        self.b, self.p = b, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.p + n > len(self.b):
            raise ValueError("short")
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def vec(self, lenbytes: int) -> bytes:
        n = int.from_bytes(self.take(lenbytes), "big")
        return self.take(n)

    def left(self) -> int:
        return len(self.b) - self.p


def _extensions(r: _Reader) -> list[tuple[int, bytes]]:
    if r.left() < 2:
        return []
    data = _Reader(r.vec(2))
    out = []
    while data.left() >= 4:
        et = data.u16()
        out.append((et, data.vec(2)))
    return out


def _u16_list(b: bytes) -> list[int]:
    return [struct.unpack(">H", b[i:i + 2])[0] for i in range(0, len(b) - 1, 2)]


@dataclass(slots=True)
class ClientHello:
    version: int
    ciphers: list[int]
    extensions: list[int]
    groups: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)

    @property
    def ja3_string(self) -> str:
        def j(vals):
            return "-".join(str(v) for v in vals if not is_grease(v))
        return ",".join([str(self.version), j(self.ciphers), j(self.extensions), j(self.groups), j(self.point_formats)])

    @property
    def ja3(self) -> str:
        return hashlib.md5(self.ja3_string.encode("ascii"), usedforsecurity=False).hexdigest()


def parse_client_hello(body: bytes) -> ClientHello | None:
    try:
        r = _Reader(body)
        version = r.u16()
        r.take(32)
        r.vec(1)
        ciphers = _u16_list(r.vec(2))
        r.vec(1)
        exts = _extensions(r)
    except ValueError:
        return None
    ch = ClientHello(version, ciphers, [e for e, _ in exts])
    for et, data in exts:
        try:
            er = _Reader(data)
            if et == 0:
                lst = _Reader(er.vec(2))
                while lst.left() >= 3:
                    ntype = lst.u8()
                    name = lst.vec(2)
                    if ntype == 0:
                        ch.sni = name.decode("ascii", "replace")
                        break
            elif et == 10:
                ch.groups = _u16_list(er.vec(2))
            elif et == 11:
                ch.point_formats = list(er.vec(1))
            elif et == 16:
                lst = _Reader(er.vec(2))
                while lst.left() >= 1:
                    ch.alpn.append(lst.vec(1).decode("ascii", "replace"))
            elif et == 43:
                ch.supported_versions = [v for v in _u16_list(er.vec(1)) if not is_grease(v)]
        except ValueError:
            continue
    return ch


@dataclass(slots=True)
class ServerHello:
    version: int
    cipher: int
    extensions: list[int]
    selected_version: int | None = None

    @property
    def ja3s_string(self) -> str:
        return f"{self.version},{self.cipher}," + "-".join(str(e) for e in self.extensions)

    @property
    def ja3s(self) -> str:
        return hashlib.md5(self.ja3s_string.encode("ascii"), usedforsecurity=False).hexdigest()


def parse_server_hello(body: bytes) -> ServerHello | None:
    try:
        r = _Reader(body)
        version = r.u16()
        r.take(32)
        r.vec(1)
        cipher = r.u16()
        r.u8()
        exts = _extensions(r)
    except ValueError:
        return None
    sh = ServerHello(version, cipher, [e for e, _ in exts])
    for et, data in exts:
        if et == 43 and len(data) == 2:
            sh.selected_version = struct.unpack(">H", data)[0]
    return sh


def parse_certificates(body: bytes, limit: int = 8) -> list[bytes]:
    try:
        chain = _Reader(_Reader(body).vec(3))
    except ValueError:
        return []
    out = []
    while chain.left() >= 3 and len(out) < limit:
        try:
            out.append(chain.vec(3))
        except ValueError:
            break
    return out


def describe_certificate(der: bytes) -> dict[str, Any]:
    """Subject/issuer/validity of a DER certificate; ``{"error": ...}`` when it does not parse."""
    info: dict[str, Any] = {"sha256": hashlib.sha256(der).hexdigest(), "sha1": hashlib.sha1(der, usedforsecurity=False).hexdigest()}
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
        info["serial"] = format(cert.serial_number, "x")
        nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
        info["not_before_ns"] = int(nb.timestamp()) * 1_000_000_000
        info["not_after_ns"] = int(na.timestamp()) * 1_000_000_000
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            info["san"] = sorted(str(n) for n in san.get_values_for_type(x509.DNSName))[:100]
        except Exception:  # noqa: BLE001 - extension absent or malformed
            pass
        info["self_signed"] = cert.subject == cert.issuer
    except Exception as exc:  # noqa: BLE001 - hostile DER must not escape
        info["error"] = type(exc).__name__
    return info
