"""HTTP/1.x message parsing over a reassembled TCP byte stream (one direction).

Handles pipelining, ``Content-Length``, chunked transfer coding and read-until-close bodies, and
decodes ``gzip``/``deflate`` content coding with an output cap (decompression bombs,
docs/THREAT_MODEL.md T3.5). Never raises on malformed input.
"""
from __future__ import annotations

import re
import zlib
from dataclasses import dataclass, field

MAX_HEADER_BLOCK = 64 * 1024
MAX_DECODED_BODY = 64 * 1024 * 1024
METHODS = (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"CONNECT", b"TRACE", b"PATCH",
           b"PROPFIND", b"PROPPATCH", b"MKCOL", b"COPY", b"MOVE", b"LOCK", b"UNLOCK", b"SEARCH")
_REQ_RE = re.compile(rb"^([A-Z]{3,12}) (\S{1,8192}) HTTP/(\d)\.(\d)$")
_RESP_RE = re.compile(rb"^HTTP/(\d)\.(\d) (\d{3})(?: (.*))?$")


def looks_like_http_request(buf: bytes) -> bool:
    return any(buf.startswith(m + b" ") for m in METHODS)


def looks_like_http_response(buf: bytes) -> bool:
    return buf.startswith(b"HTTP/1.")


@dataclass(slots=True)
class HttpMessage:
    offset: int  # offset of the first byte in the stream
    is_request: bool
    method: str = ""
    uri: str = ""
    version: str = ""
    status: int | None = None
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""  # after transfer decoding (dechunked), before content decoding
    body_complete: bool = True
    decoded_body: bytes | None = None  # after content decoding, when applicable
    decode_error: str | None = None

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    @property
    def entity(self) -> bytes:
        return self.decoded_body if self.decoded_body is not None else self.body


def _dechunk(buf: bytes, pos: int) -> tuple[bytes, int, bool]:
    out = bytearray()
    while True:
        eol = buf.find(b"\r\n", pos)
        if eol < 0 or eol - pos > 1024:
            return bytes(out), len(buf), False
        size_txt = buf[pos:eol].split(b";", 1)[0].strip()
        try:
            size = int(size_txt, 16)
        except ValueError:
            return bytes(out), len(buf), False
        pos = eol + 2
        if size == 0:
            # trailers end with an empty line
            end = buf.find(b"\r\n\r\n", pos - 2)
            return bytes(out), (end + 4 if end >= 0 else len(buf)), True
        chunk = buf[pos:pos + size]
        out += chunk
        if len(chunk) < size:
            return bytes(out), len(buf), False
        pos += size + 2


def _decode_content(msg: HttpMessage) -> None:
    enc = (msg.header("Content-Encoding") or "").strip().lower()
    if not enc or enc == "identity" or not msg.body:
        return
    if enc in ("gzip", "x-gzip"):
        wbits = 16 + zlib.MAX_WBITS
    elif enc == "deflate":
        wbits = zlib.MAX_WBITS if msg.body[:1] == b"\x78" else -zlib.MAX_WBITS
    else:
        msg.decode_error = f"unsupported content-encoding {enc}"
        return
    try:
        d = zlib.decompressobj(wbits)
        out = d.decompress(msg.body, MAX_DECODED_BODY)
        if d.unconsumed_tail:
            msg.decode_error = "decoded body exceeds cap"
        msg.decoded_body = out
    except zlib.error as exc:
        msg.decode_error = f"zlib: {exc}"


def parse_stream(buf: bytes, is_request: bool, request_methods: list[str] | None = None,
                 max_messages: int = 10_000) -> list[HttpMessage]:
    """Parse consecutive HTTP messages. ``request_methods`` pairs responses with HEAD requests."""
    msgs: list[HttpMessage] = []
    pos = 0
    methods = list(request_methods or [])
    while pos < len(buf) and len(msgs) < max_messages:
        start = pos
        end = buf.find(b"\r\n\r\n", pos, pos + MAX_HEADER_BLOCK)
        sep = 4
        if end < 0:
            end = buf.find(b"\n\n", pos, pos + MAX_HEADER_BLOCK)
            sep = 2
        if end < 0:
            break
        lines = buf[pos:end].replace(b"\r\n", b"\n").split(b"\n")
        first = lines[0]
        msg = HttpMessage(offset=start, is_request=is_request)
        if is_request:
            m = _REQ_RE.match(first)
            if not m:
                break
            msg.method = m.group(1).decode("ascii")
            msg.uri = m.group(2).decode("latin-1")
            msg.version = f"{m.group(3).decode()}.{m.group(4).decode()}"
        else:
            m = _RESP_RE.match(first)
            if not m:
                break
            msg.version = f"{m.group(1).decode()}.{m.group(2).decode()}"
            msg.status = int(m.group(3))
            msg.reason = (m.group(4) or b"").decode("latin-1")
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                msg.headers.append((k.strip().decode("latin-1"), v.strip().decode("latin-1")))
        pos = end + sep
        te = (msg.header("Transfer-Encoding") or "").lower()
        cl = msg.header("Content-Length")
        req_method = methods[len(msgs)] if not is_request and len(msgs) < len(methods) else ""
        no_body = (not is_request and (msg.status is not None and (msg.status < 200 or msg.status in (204, 304))
                                       or req_method == "HEAD"))
        if no_body:
            pass
        elif "chunked" in te:
            msg.body, pos, msg.body_complete = _dechunk(buf, pos)
        elif cl is not None and cl.strip().isdigit():
            n = int(cl.strip())
            msg.body = buf[pos:pos + n]
            msg.body_complete = len(msg.body) == n
            pos += n
        elif not is_request:
            msg.body = buf[pos:]
            pos = len(buf)
        _decode_content(msg)
        msgs.append(msg)
        if pos <= start:
            break
    return msgs


def sniff_mime(data: bytes) -> str:
    """Content sniffing by magic, independent of what the server claimed."""
    sigs = (
        (b"MZ", "application/x-dosexec"), (b"\x7fELF", "application/x-executable"),
        (b"PK\x03\x04", "application/zip"), (b"%PDF", "application/pdf"), (b"\x89PNG", "image/png"),
        (b"GIF8", "image/gif"), (b"\xff\xd8\xff", "image/jpeg"), (b"\x1f\x8b", "application/gzip"),
        (b"Rar!", "application/x-rar"), (b"7z\xbc\xaf", "application/x-7z-compressed"),
        (b"\xd0\xcf\x11\xe0", "application/x-ole-storage"), (b"\xca\xfe\xba\xbe", "application/x-mach-binary"),
        (b"\xcf\xfa\xed\xfe", "application/x-mach-binary"), (b"\x00\x00\x01\x00", "image/x-icon"),
        (b"RIFF", "application/x-riff"), (b"<?xml", "text/xml"),
    )
    for sig, mime in sigs:
        if data.startswith(sig):
            return mime
    head = data[:512].lstrip().lower()
    if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
        return "text/html"
    if head[:1] in (b"{", b"["):
        return "application/json"
    if data and all(32 <= b < 127 or b in (9, 10, 13) for b in data[:512]):
        return "text/plain"
    return "application/octet-stream"
