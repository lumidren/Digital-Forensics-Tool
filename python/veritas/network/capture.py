"""Exact-timestamp pcap / pcapng record reader.

dpkt's readers return float timestamps, which lose nanosecond precision and are not
reproducible across platforms. This reader decodes the record headers itself and yields integer
nanoseconds plus the byte offset of every record, so events can point back into the capture.
Protocol decoding above the link layer is left to dpkt.

Malformed input never raises out of :func:`iter_packets`: a corrupt header stops iteration and
is reported through the ``warn`` callback.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Callable, Iterator

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),  # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),  # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1),
}
PCAPNG_SHB = 0x0A0D0D0A
MAX_RECORD = 16 * 1024 * 1024  # larger capture lengths only occur in corrupt files
NS = 1_000_000_000


@dataclass(slots=True)
class RawPacket:
    index: int
    ts_ns: int | None
    linktype: int
    data: bytes
    orig_len: int
    file_offset: int


def sniff_format(head: bytes) -> str | None:
    if head[:4] in PCAP_MAGICS:
        return "pcap"
    if len(head) >= 4 and struct.unpack("<I", head[:4])[0] == PCAPNG_SHB:
        return "pcapng"
    return None


def _iter_pcap(fh: BinaryIO, warn: Callable[[str], None]) -> Iterator[RawPacket]:
    hdr = fh.read(24)
    if len(hdr) < 24:
        warn("pcap: truncated global header")
        return
    endian, frac_mult = PCAP_MAGICS[hdr[:4]]
    _vmaj, _vmin, _zone, _sigfigs, _snaplen, network = struct.unpack(endian + "HHiIII", hdr[4:24])
    linktype = network & 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    offset, index = 24, 0
    while True:
        h = fh.read(16)
        if not h:
            return
        if len(h) < 16:
            warn(f"pcap: truncated record header at offset {offset}")
            return
        sec, frac, incl, orig = rec.unpack(h)
        if incl > MAX_RECORD:
            warn(f"pcap: implausible capture length {incl} at offset {offset}; stopping")
            return
        data = fh.read(incl)
        if len(data) < incl:
            warn(f"pcap: truncated packet data at offset {offset}")
            return
        if frac_mult == 1_000 and frac >= 1_000_000 or frac_mult == 1 and frac >= NS:
            warn(f"pcap: record {index} has out-of-range fractional timestamp {frac}")
        yield RawPacket(index, sec * NS + frac * frac_mult, linktype, data, orig, offset)
        offset += 16 + incl
        index += 1


def _ts_to_ns(units: int, resol: tuple[bool, int], tsoffset_s: int) -> int:
    binary, exp = resol
    if binary:
        ns = (units * NS) >> exp
    elif exp <= 9:
        ns = units * 10 ** (9 - exp)
    else:
        ns = units // 10 ** (exp - 9)
    return ns + tsoffset_s * NS


def _iter_options(body: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    pos = 0
    while pos + 4 <= len(body):
        code, length = struct.unpack(endian + "HH", body[pos:pos + 4])
        if code == 0:
            return
        val = body[pos + 4:pos + 4 + length]
        if len(val) < length:
            return
        yield code, val
        pos += 4 + ((length + 3) & ~3)


def _iter_pcapng(fh: BinaryIO, warn: Callable[[str], None]) -> Iterator[RawPacket]:
    endian = "<"
    ifaces: list[tuple[int, tuple[bool, int], int, int]] = []  # linktype, resol, tsoffset, snaplen
    offset, index = 0, 0
    while True:
        head = fh.read(8)
        if not head:
            return
        if len(head) < 8:
            warn(f"pcapng: truncated block header at offset {offset}")
            return
        btype_le = struct.unpack("<I", head[:4])[0]
        if btype_le == PCAPNG_SHB:
            bom = fh.read(4)
            if len(bom) < 4:
                warn("pcapng: truncated section header")
                return
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                warn(f"pcapng: bad byte-order magic at offset {offset}")
                return
            blen = struct.unpack(endian + "I", head[4:8])[0]
            if blen < 28 or blen % 4 or blen > MAX_RECORD:
                warn(f"pcapng: bad section header length {blen} at offset {offset}")
                return
            rest = fh.read(blen - 12)
            if len(rest) < blen - 12:
                warn("pcapng: truncated section header")
                return
            ifaces = []
            offset += blen
            continue
        btype, blen = struct.unpack(endian + "II", head)
        if blen < 12 or blen % 4 or blen > MAX_RECORD:
            warn(f"pcapng: bad block length {blen} at offset {offset}; stopping")
            return
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            warn(f"pcapng: truncated block at offset {offset}")
            return
        body = body[:-4]  # trailing length copy
        try:
            if btype == 0x00000001:  # Interface Description Block
                linktype, _res, snaplen = struct.unpack(endian + "HHI", body[:8])
                resol, tsoff = (False, 6), 0
                for code, val in _iter_options(body[8:], endian):
                    if code == 9 and val:
                        resol = (bool(val[0] & 0x80), val[0] & 0x7F)
                    elif code == 14 and len(val) >= 8:
                        tsoff = struct.unpack(endian + "q", val[:8])[0]
                if resol[1] > 30 and resol[0] or resol[1] > 18 and not resol[0]:
                    warn(f"pcapng: implausible timestamp resolution {resol}; using microseconds")
                    resol = (False, 6)
                ifaces.append((linktype, resol, tsoff, snaplen))
            elif btype in (0x00000006, 0x00000002):  # Enhanced / obsolete Packet Block
                if btype == 6:
                    iface, ts_hi, ts_lo, caplen, origlen = struct.unpack(endian + "IIIII", body[:20])
                else:
                    iface, _drops, ts_hi, ts_lo, caplen, origlen = struct.unpack(endian + "HHIIII", body[:20])
                if iface >= len(ifaces):
                    warn(f"pcapng: packet references unknown interface {iface} at offset {offset}")
                else:
                    linktype, resol, tsoff, _snap = ifaces[iface]
                    data = body[20:20 + caplen]
                    if len(data) < caplen:
                        warn(f"pcapng: packet data shorter than caplen at offset {offset}")
                    ts = _ts_to_ns((ts_hi << 32) | ts_lo, resol, tsoff)
                    yield RawPacket(index, ts, linktype, data, origlen, offset)
                    index += 1
            elif btype == 0x00000003:  # Simple Packet Block (no timestamp, interface 0)
                if not ifaces:
                    warn(f"pcapng: simple packet before any interface at offset {offset}")
                else:
                    origlen = struct.unpack(endian + "I", body[:4])[0]
                    linktype, _r, _o, snap = ifaces[0]
                    cap = min(origlen, snap or origlen, len(body) - 4)
                    yield RawPacket(index, None, linktype, body[4:4 + cap], origlen, offset)
                    index += 1
            # other block types (NRB, ISB, DSB, custom) carry no packets
        except struct.error:
            warn(f"pcapng: malformed block type 0x{btype:x} at offset {offset}")
        offset += blen


def iter_packets(fh: BinaryIO, warn: Callable[[str], None]) -> Iterator[RawPacket]:
    head = fh.read(4)
    fh.seek(0)
    fmt = sniff_format(head)
    if fmt == "pcap":
        yield from _iter_pcap(fh, warn)
    elif fmt == "pcapng":
        yield from _iter_pcapng(fh, warn)
    else:
        warn("not a pcap or pcapng file")
