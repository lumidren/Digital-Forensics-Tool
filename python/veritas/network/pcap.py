"""Native PCAP / PCAPNG analysis (no Zeek required).

Produces, as :class:`~veritas.timeline.schema.Event` objects:

* ``network:conn``                 one per flow (5-tuple, packets, payload bytes, first/last seen,
                                   TCP flag history, detected service)
* ``network:dns``                  queries and responses (UDP and TCP), with answers and rcode
* ``network:http:request``         method, host, URI, user agent, referrer, response status/type
* ``network:file``                 HTTP bodies (both directions): size, md5/sha1/sha256, claimed and
                                   sniffed MIME type, file name; optionally written to
                                   ``extract_dir/<sha256>`` (content addressed, never overwritten)
* ``network:tls:client_hello``     SNI, ALPN, offered versions, JA3 and JA3 string
* ``network:tls:server_hello``     negotiated version/cipher, JA3S
* ``network:tls:certificate``      subject, issuer, serial, validity, SHA-256 fingerprint

Record headers are decoded by :mod:`veritas.network.capture` (integer ns timestamps, file
offsets), protocols by dpkt. TCP payloads of HTTP/TLS/DNS flows are reassembled per direction
by sequence number (first copy wins, a gap ends the usable stream) up to ``max_stream_bytes``.
Malformed packets are counted warnings. Nothing reads the wall clock.
"""
from __future__ import annotations

import bisect
import hashlib
import os
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Iterator

import dpkt

from veritas.network import http as httpp
from veritas.network import tls
from veritas.network.capture import RawPacket, iter_packets, sniff_format
from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.timeline.schema import Desc, Event, sorted_events

VERSION = "1.0"

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
             35: "NAPTR", 39: "DNAME", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
DNS_PORTS = (53, 5353, 5355)
TCP_FLAGS = ((dpkt.tcp.TH_SYN, "S"), (dpkt.tcp.TH_FIN, "F"), (dpkt.tcp.TH_RST, "R"), (dpkt.tcp.TH_PUSH, "P"))


def _ip_str(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6 if len(raw) == 16 else socket.AF_INET, raw)


# --------------------------------------------------------------------------- link layer
def decode_l3(linktype: int, data: bytes) -> Any:
    """Return a dpkt IP/IP6 object (or None) for the supported link types."""
    payload: bytes | None
    if linktype == 1:  # Ethernet (dpkt handles 802.1Q/QinQ and MPLS)
        eth = dpkt.ethernet.Ethernet(data)
        l3 = eth.data
        return l3 if isinstance(l3, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if linktype == 0 or linktype == 108:  # BSD loopback / OpenBSD loop
        payload = data[4:]
    elif linktype in (101, 12, 14, 228, 229):  # raw IP
        payload = data
    elif linktype == 113:  # Linux cooked v1
        l3 = dpkt.sll.SLL(data).data
        return l3 if isinstance(l3, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    elif linktype == 276:  # Linux cooked v2: 20-byte header, ethertype first
        if len(data) < 20:
            return None
        etype = struct.unpack(">H", data[:2])[0]
        payload = data[20:] if etype in (0x0800, 0x86DD) else None
    else:
        return None
    if not payload:
        return None
    ver = payload[0] >> 4
    if ver == 4:
        return dpkt.ip.IP(payload)
    if ver == 6:
        return dpkt.ip6.IP6(payload)
    return None


# --------------------------------------------------------------------------- flows
@dataclass(slots=True)
class _Direction:
    base: int | None = None  # absolute seq of stream byte 0
    segs: dict[int, tuple[bytes, int | None]] = field(default_factory=dict)  # rel offset -> payload, ts
    buffered: int = 0
    truncated: bool = False

    def add(self, seq: int, payload: bytes, ts: int | None, cap: int) -> None:
        if self.base is None:
            self.base = seq
        rel = (seq - self.base) & 0xFFFFFFFF
        if rel >= 0x80000000:  # before the stream start (retransmitted handshake data)
            return
        if rel in self.segs:
            return
        if self.buffered + len(payload) > cap:
            self.truncated = True
            return
        self.segs[rel] = (payload, ts)
        self.buffered += len(payload)

    def assemble(self) -> tuple[bytes, list[int], list[int | None], bool]:
        out = bytearray()
        marks: list[int] = []
        times: list[int | None] = []
        gap = False
        for rel in sorted(self.segs):
            payload, ts = self.segs[rel]
            cur = len(out)
            if rel + len(payload) <= cur:
                continue
            if rel > cur:
                gap = True
                break
            marks.append(cur)
            times.append(ts)
            out += payload[cur - rel:]
        return bytes(out), marks, times, gap


@dataclass(slots=True)
class Flow:
    proto: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    first_ns: int | None
    last_ns: int | None
    first_offset: int
    first_index: int
    orig_pkts: int = 0
    orig_bytes: int = 0
    resp_pkts: int = 0
    resp_bytes: int = 0
    history: str = ""
    service: str = ""
    stream: bool = True  # still buffering payload for content analysis
    dirs: tuple[_Direction, _Direction] = field(default_factory=lambda: (_Direction(), _Direction()))

    @property
    def uid(self) -> str:
        key = f"{self.proto}|{self.orig_h}|{self.orig_p}|{self.resp_h}|{self.resp_p}|{self.first_ns}|{self.first_index}"
        return "C" + hashlib.sha256(key.encode()).hexdigest()[:17]

    def to_attrs(self) -> dict[str, Any]:
        dur = (self.last_ns - self.first_ns) if self.first_ns is not None and self.last_ns is not None else None
        return {
            "uid": self.uid, "proto": self.proto, "orig_h": self.orig_h, "orig_p": self.orig_p,
            "resp_h": self.resp_h, "resp_p": self.resp_p, "orig_pkts": self.orig_pkts,
            "orig_bytes": self.orig_bytes, "resp_pkts": self.resp_pkts, "resp_bytes": self.resp_bytes,
            "first_ns": self.first_ns, "last_ns": self.last_ns, "duration_ns": dur,
            "history": self.history, "service": self.service or None,
        }


@dataclass(slots=True)
class PcapReport:
    path: str
    format: str | None = None
    packets: int = 0
    linktypes: list[int] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    files: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    warning_count: int = 0


class PcapParser(BaseParser):
    name = "pcap"
    version = VERSION
    source_short = "NET"
    source_long = "Packet capture"

    def __init__(self, *, extract_dir: str | None = None, max_stream_bytes: int = 16 * 1024 * 1024,
                 max_flows: int = 2_000_000) -> None:
        super().__init__()
        self.extract_dir = extract_dir
        self.max_stream_bytes = max_stream_bytes
        self.max_flows = max_flows

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return sniff_format(head_bytes[:4]) is not None

    # ------------------------------------------------------------------ main loop
    def analyze(self, path: str, provenance: Provenance | None = None) -> PcapReport:
        self.warnings, self.warning_count = [], 0
        self._prov = provenance or Provenance(evidence_path=os.path.basename(path))
        report = PcapReport(path=path)
        flows: dict[tuple, Flow] = {}
        events: list[Event] = []
        linktypes: set[int] = set()
        try:
            fh = open(path, "rb")
        except OSError as exc:
            raise ParserError(f"cannot open capture: {exc}") from exc
        with fh:
            report.format = sniff_format(fh.read(4))
            fh.seek(0)
            if report.format is None:
                raise ParserError("not a pcap or pcapng file")
            for pkt in iter_packets(fh, self.warn):
                report.packets += 1
                linktypes.add(pkt.linktype)
                try:
                    self._packet(pkt, flows, events)
                except (dpkt.UnpackError, dpkt.NeedData, struct.error, ValueError, IndexError, OSError) as exc:
                    self.warn(f"packet {pkt.index} at offset {pkt.file_offset}: {type(exc).__name__}: {exc}")
        ordered = sorted(flows.values(), key=lambda f: (f.first_index, f.uid))
        for fl in ordered:
            try:
                events.extend(self._flow_content(fl, report))
            except Exception as exc:  # noqa: BLE001 - one flow must not abort the capture
                self.warn(f"flow {fl.uid}: {type(exc).__name__}: {exc}")
            events.append(self._conn_event(fl))
        report.flows = ordered
        report.linktypes = sorted(linktypes)
        report.events = sorted_events(events)
        report.warnings, report.warning_count = list(self.warnings), self.warning_count
        return report

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        yield from self.analyze(path, prov).events

    # ------------------------------------------------------------------ per packet
    def _packet(self, pkt: RawPacket, flows: dict[tuple, Flow], events: list[Event]) -> None:
        ip = decode_l3(pkt.linktype, pkt.data)
        if ip is None:
            return
        if isinstance(ip, dpkt.ip.IP):
            if ip.offset:
                return  # non-first fragment: no L4 header
            proto_num = ip.p
        else:
            proto_num = ip.nxt
        src, dst = _ip_str(bytes(ip.src)), _ip_str(bytes(ip.dst))
        l4 = ip.data
        flags = 0
        seq = 0
        if isinstance(l4, dpkt.tcp.TCP):
            proto, sport, dport, payload = "tcp", l4.sport, l4.dport, bytes(l4.data)
            flags, seq = l4.flags, l4.seq
        elif isinstance(l4, dpkt.udp.UDP):
            proto, sport, dport, payload = "udp", l4.sport, l4.dport, bytes(l4.data)
        elif isinstance(l4, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
            proto, sport, dport, payload = ("icmp" if isinstance(l4, dpkt.icmp.ICMP) else "icmp6"), l4.type, l4.code, b""
        else:
            proto, sport, dport, payload = f"ip{proto_num}", 0, 0, b""

        key_a, key_b = (src, sport), (dst, dport)
        key = (proto,) + (key_a + key_b if key_a <= key_b else key_b + key_a)
        fl = flows.get(key)
        if fl is None:
            if len(flows) >= self.max_flows:
                if len(flows) == self.max_flows:
                    self.warn(f"flow table limit {self.max_flows} reached; further new flows ignored")
                return
            orig_is_src = True
            if proto == "tcp":
                syn, ack = flags & dpkt.tcp.TH_SYN, flags & dpkt.tcp.TH_ACK
                if syn and ack:
                    orig_is_src = False
                elif not syn and sport < 1024 <= dport:
                    orig_is_src = False
            elif proto == "udp" and sport < 1024 <= dport and sport in DNS_PORTS:
                orig_is_src = False
            o, r = (key_a, key_b) if orig_is_src else (key_b, key_a)
            fl = Flow(proto, o[0], o[1], r[0], r[1], pkt.ts_ns, pkt.ts_ns, pkt.file_offset, pkt.index)
            fl.stream = proto == "tcp"
            flows[key] = fl
        from_orig = (src, sport) == (fl.orig_h, fl.orig_p)
        if pkt.ts_ns is not None:
            fl.first_ns = pkt.ts_ns if fl.first_ns is None else min(fl.first_ns, pkt.ts_ns)
            fl.last_ns = pkt.ts_ns if fl.last_ns is None else max(fl.last_ns, pkt.ts_ns)
        if from_orig:
            fl.orig_pkts += 1
            fl.orig_bytes += len(payload)
        else:
            fl.resp_pkts += 1
            fl.resp_bytes += len(payload)

        if proto == "tcp":
            for bit, ch in TCP_FLAGS:
                if flags & bit:
                    c = ch if from_orig else ch.lower()
                    if c not in fl.history and len(fl.history) < 32:
                        fl.history += c
            d = fl.dirs[0 if from_orig else 1]
            if flags & dpkt.tcp.TH_SYN:
                d.base = (seq + 1) & 0xFFFFFFFF
            if payload and fl.stream:
                d.add(seq, payload, pkt.ts_ns, self.max_stream_bytes)
                self._decide_stream(fl)
        elif proto == "udp" and (sport in DNS_PORTS or dport in DNS_PORTS) and payload:
            fl.service = fl.service or "dns"
            events.extend(self._dns_events(payload, pkt.ts_ns, pkt.file_offset, fl, from_orig))

    def _decide_stream(self, fl: Flow) -> None:
        """Keep buffering only flows whose client speaks HTTP, TLS or DNS-over-TCP."""
        if fl.service:
            return
        if fl.orig_p in DNS_PORTS or fl.resp_p in DNS_PORTS:
            fl.service = "dns"
            return
        d = fl.dirs[0]
        head = b"".join(p for _, (p, _t) in sorted(d.segs.items())[:4])[:16]
        if len(head) < 8:
            if fl.dirs[1].buffered > 4096 and not d.segs:
                fl.stream = False  # server-first protocol
                fl.dirs[0].segs.clear()
                fl.dirs[1].segs.clear()
            return
        if httpp.looks_like_http_request(head):
            fl.service = "http"
        elif tls.looks_like_tls(head):
            fl.service = "ssl"
        else:
            fl.stream = False
            for dd in fl.dirs:
                dd.segs.clear()
                dd.buffered = 0

    # ------------------------------------------------------------------ DNS
    def _dns_events(self, payload: bytes, ts: int | None, offset: int, fl: Flow, from_orig: bool) -> list[Event]:
        try:
            msg = dpkt.dns.DNS(payload)
        except (dpkt.UnpackError, dpkt.NeedData, struct.error, IndexError, ValueError) as exc:
            self.warn(f"DNS decode failed in flow {fl.uid} at offset {offset}: {type(exc).__name__}")
            return []
        out = []
        client, server = (fl.orig_h, fl.resp_h)
        is_resp = bool(msg.qr)
        answers = []
        for rr in list(msg.an)[:100]:
            answers.append(self._rr_text(rr))
        for q in list(msg.qd)[:16]:
            qtype = DNS_TYPES.get(q.type, str(q.type))
            attrs = {
                "uid": fl.uid, "trans_id": msg.id, "query": q.name, "qtype": qtype, "qclass": q.cls,
                "is_response": is_resp, "client": client, "server": server, "proto": fl.proto,
                "orig_p": fl.orig_p, "resp_p": fl.resp_p,
            }
            if is_resp:
                rcode = DNS_RCODES.get(msg.rcode, str(msg.rcode))
                attrs.update({"rcode": rcode, "answers": answers, "authoritative": bool(msg.aa)})
                text = f"DNS response {q.name} {qtype} {rcode}" + (": " + ", ".join(answers[:10]) if answers else "")
                out.append(self.event("network:dns", Desc.RECEIVED, text, ts, offset=offset, attrs=attrs))
            else:
                out.append(self.event("network:dns", Desc.SENT, f"DNS query {q.name} {qtype}", ts, offset=offset, attrs=attrs))
        return out

    @staticmethod
    def _rr_text(rr: Any) -> str:
        t = rr.type
        try:
            if t == dpkt.dns.DNS_A:
                return socket.inet_ntop(socket.AF_INET, rr.ip)
            if t == dpkt.dns.DNS_AAAA:
                return socket.inet_ntop(socket.AF_INET6, rr.ip6)
            if t == dpkt.dns.DNS_CNAME:
                return rr.cname
            if t == dpkt.dns.DNS_PTR:
                return rr.ptrname
            if t == dpkt.dns.DNS_MX:
                return rr.mxname
            if t == dpkt.dns.DNS_NS:
                return rr.nsname
            if t == dpkt.dns.DNS_TXT:
                return " ".join(x.decode("utf-8", "replace") if isinstance(x, bytes) else str(x) for x in rr.text)
        except (AttributeError, ValueError, OSError):
            pass
        return f"{DNS_TYPES.get(t, t)}:{bytes(rr.rdata).hex()[:64]}"

    # ------------------------------------------------------------------ TCP content
    def _flow_content(self, fl: Flow, report: PcapReport) -> list[Event]:
        if fl.proto != "tcp" or not fl.stream or not fl.service:
            return []
        streams = []
        for i, d in enumerate(fl.dirs):
            data, marks, times, gap = d.assemble()
            if d.truncated:
                self.warn(f"flow {fl.uid}: direction {i} exceeds {self.max_stream_bytes} bytes; truncated")
            streams.append((data, marks, times, gap))

        def ts_at(direction: int, off: int) -> int | None:
            _d, marks, times, _g = streams[direction]
            if not marks:
                return fl.first_ns
            i = bisect.bisect_right(marks, off) - 1
            return times[max(i, 0)]

        if fl.service == "http":
            return self._http_events(fl, streams, ts_at, report)
        if fl.service == "ssl":
            return self._tls_events(fl, streams, ts_at)
        if fl.service == "dns":
            out = []
            for direction in (0, 1):
                data = streams[direction][0]
                pos = 0
                while pos + 2 <= len(data):
                    n = struct.unpack(">H", data[pos:pos + 2])[0]
                    chunk = data[pos + 2:pos + 2 + n]
                    if len(chunk) < n or n == 0:
                        break
                    out += self._dns_events(chunk, ts_at(direction, pos), fl.first_offset, fl, direction == 0)
                    pos += 2 + n
            return out
        return []

    def _http_events(self, fl: Flow, streams, ts_at, report: PcapReport) -> list[Event]:
        out: list[Event] = []
        reqs = httpp.parse_stream(streams[0][0], True)
        resps = httpp.parse_stream(streams[1][0], False, [r.method for r in reqs])
        for i, req in enumerate(reqs):
            resp = resps[i] if i < len(resps) else None
            host = req.header("Host") or fl.resp_h
            url = req.uri if req.uri.lower().startswith(("http://", "https://")) else f"http://{host}{req.uri}"
            attrs = {
                "uid": fl.uid, "method": req.method, "host": host, "uri": req.uri, "url": url,
                "version": req.version, "user_agent": req.header("User-Agent"), "referrer": req.header("Referer"),
                "orig_h": fl.orig_h, "orig_p": fl.orig_p, "resp_h": fl.resp_h, "resp_p": fl.resp_p,
                "request_body_len": len(req.body),
            }
            if resp is not None:
                attrs.update({
                    "status_code": resp.status, "status_msg": resp.reason,
                    "response_content_type": resp.header("Content-Type"),
                    "response_body_len": len(resp.entity), "server": resp.header("Server"),
                })
            msg = f"HTTP {req.method} {url}" + (f" -> {resp.status}" if resp is not None else "")
            out.append(self.event("network:http:request", Desc.SENT, msg, ts_at(0, req.offset),
                                  offset=fl.first_offset, attrs=attrs))
            if req.body:
                out.append(self._file_event(fl, req, url, "orig", ts_at(0, req.offset), report))
            if resp is not None and resp.entity:
                out.append(self._file_event(fl, resp, url, "resp", ts_at(1, resp.offset), report))
        return out

    def _file_event(self, fl: Flow, msg: httpp.HttpMessage, url: str, direction: str, ts: int | None,
                    report: PcapReport) -> Event:
        data = msg.entity
        sha256 = hashlib.sha256(data).hexdigest()
        info = {
            "uid": fl.uid, "source": "HTTP", "url": url, "direction": direction, "size": len(data),
            "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
            "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(), "sha256": sha256,
            "claimed_mime": msg.header("Content-Type"), "mime": httpp.sniff_mime(data),
            "complete": msg.body_complete and msg.decode_error is None,
            "content_encoding": msg.header("Content-Encoding"), "decode_error": msg.decode_error,
            "filename": self._filename(msg, url),
            "tx_h": fl.resp_h if direction == "resp" else fl.orig_h,
            "rx_h": fl.orig_h if direction == "resp" else fl.resp_h,
        }
        if self.extract_dir:
            os.makedirs(self.extract_dir, exist_ok=True)
            target = os.path.join(self.extract_dir, sha256)
            if not os.path.exists(target):
                with open(target, "xb") as fh:
                    fh.write(data)
            info["extracted_path"] = target
        report.files.append(info)
        text = f"File {info['filename'] or '-'} {len(data)} bytes {info['mime']} sha256={sha256} via HTTP {url}"
        return self.event("network:file", Desc.RECEIVED, text, ts, offset=fl.first_offset, attrs=info)

    @staticmethod
    def _filename(msg: httpp.HttpMessage, url: str) -> str | None:
        cd = msg.header("Content-Disposition") or ""
        if "filename=" in cd.lower():
            v = cd[cd.lower().index("filename=") + 9:].split(";")[0].strip().strip('"')
            return os.path.basename(v.replace("\\", "/")) or None
        path = url.split("?", 1)[0].split("#", 1)[0]
        tail = path.rsplit("/", 1)[-1]
        return tail or None

    def _tls_events(self, fl: Flow, streams, ts_at) -> list[Event]:
        out: list[Event] = []
        base = {"uid": fl.uid, "orig_h": fl.orig_h, "orig_p": fl.orig_p, "resp_h": fl.resp_h, "resp_p": fl.resp_p}
        sni = None
        for htype, body, complete in tls.iter_handshakes(tls.handshake_bytes(streams[0][0])):
            if htype == 1 and complete:
                ch = tls.parse_client_hello(body)
                if ch is None:
                    self.warn(f"flow {fl.uid}: malformed ClientHello")
                    break
                sni = ch.sni
                attrs = dict(base, sni=ch.sni, ja3=ch.ja3, ja3_string=ch.ja3_string,
                             version=f"0x{ch.version:04x}", alpn=ch.alpn,
                             supported_versions=[f"0x{v:04x}" for v in ch.supported_versions],
                             cipher_count=len(ch.ciphers))
                out.append(self.event("network:tls:client_hello", Desc.SENT,
                                      f"TLS ClientHello SNI={ch.sni or '-'} JA3={ch.ja3}",
                                      ts_at(0, 0), offset=fl.first_offset, attrs=attrs))
                break
        for htype, body, complete in tls.iter_handshakes(tls.handshake_bytes(streams[1][0])):
            if not complete:
                break
            if htype == 2:
                sh = tls.parse_server_hello(body)
                if sh is None:
                    self.warn(f"flow {fl.uid}: malformed ServerHello")
                    continue
                ver = sh.selected_version or sh.version
                attrs = dict(base, sni=sni, ja3s=sh.ja3s, ja3s_string=sh.ja3s_string, version=f"0x{ver:04x}",
                             cipher=f"0x{sh.cipher:04x}")
                out.append(self.event("network:tls:server_hello", Desc.RECEIVED,
                                      f"TLS ServerHello version=0x{ver:04x} cipher=0x{sh.cipher:04x} JA3S={sh.ja3s}",
                                      ts_at(1, 0), offset=fl.first_offset, attrs=attrs))
            elif htype == 11:
                for depth, der in enumerate(tls.parse_certificates(body)):
                    info = tls.describe_certificate(der)
                    attrs = dict(base, sni=sni, chain_depth=depth, **info)
                    out.append(self.event(
                        "network:tls:certificate", Desc.RECEIVED,
                        f"TLS certificate [{depth}] subject={info.get('subject', '?')} issuer={info.get('issuer', '?')}",
                        ts_at(1, 0), offset=fl.first_offset, attrs=attrs))
        return out

    # ------------------------------------------------------------------ conn
    def _conn_event(self, fl: Flow) -> Event:
        svc = f" [{fl.service}]" if fl.service else ""
        text = (f"{fl.proto.upper()} {fl.orig_h}:{fl.orig_p} -> {fl.resp_h}:{fl.resp_p}{svc} "
                f"{fl.orig_pkts + fl.resp_pkts} packets {fl.orig_bytes + fl.resp_bytes} bytes")
        return self.event("network:conn", Desc.START, text, fl.first_ns, offset=fl.first_offset, attrs=fl.to_attrs())


def _as_provenance(p: Any) -> Provenance | None:
    if p is None or isinstance(p, Provenance):
        return p
    return Provenance(evidence_sha256=getattr(p, "evidence_sha256", ""), evidence_path=getattr(p, "evidence_path", ""))


def parse(path: str, provenance: Any = None) -> Iterator[Event]:
    """Pipeline contract: yield normalised network events for a pcap/pcapng file."""
    yield from PcapParser().parse(path, _as_provenance(provenance))
