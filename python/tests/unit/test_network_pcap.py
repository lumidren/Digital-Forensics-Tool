"""Native PCAP/PCAPNG analysis on the Plaso test capture plus synthetic captures, HTTP/TLS helpers,
determinism and no-crash properties."""
from __future__ import annotations

import gzip
import hashlib
import struct
from collections import Counter
from pathlib import Path

import dpkt
import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from veritas.network import http as httpp
from veritas.network import pcap as pcapmod
from veritas.network import tls
from veritas.network.capture import iter_packets
from veritas.network.pcap import PcapParser
from veritas.parsers.base import ParserError, Provenance
from veritas.timeline.schema import Desc

FIRST_TS = 1374174706_795704000


@pytest.fixture(scope="module")
def test_pcap(corpus) -> Path:
    p = corpus / "plaso" / "test.pcap"
    if not p.is_file():
        pytest.skip("plaso/test.pcap not in corpus")
    return p


@pytest.fixture(scope="module")
def report(test_pcap):
    return PcapParser().analyze(str(test_pcap), Provenance(evidence_sha256="00" * 32, evidence_path="plaso/test.pcap"))


def by_type(rep, dt):
    return [e for e in rep.events if e.data_type == dt]


def test_counts_and_types(report):
    assert report.format == "pcap" and report.packets == 1434 and report.linktypes == [1]
    assert report.warning_count == 0
    c = Counter(e.data_type for e in report.events)
    assert c["network:conn"] == len(report.flows) == 61
    assert c["network:http:request"] == 13
    assert c["network:tls:client_hello"] == 4 and c["network:tls:server_hello"] == 4
    assert c["network:tls:certificate"] == 8
    assert c["network:dns"] == 54
    assert all(e.evidence_path == "plaso/test.pcap" and e.parser == "pcap" for e in report.events)


def test_flows(report):
    first = min(report.flows, key=lambda f: f.first_index)
    assert first.first_ns == FIRST_TS and first.first_offset == 24
    assert sum(f.orig_pkts + f.resp_pkts for f in report.flows) <= report.packets
    https = [f for f in report.flows if f.service == "ssl"]
    assert https and all(f.resp_p == 443 and f.proto == "tcp" for f in https)
    conn = by_type(report, "network:conn")
    assert all(e.timestamp_desc == Desc.START for e in conn)
    assert all(e.attrs["duration_ns"] >= 0 for e in conn)


def test_dns(report):
    dns = by_type(report, "network:dns")
    queries = {e.attrs["query"] for e in dns if not e.attrs["is_response"]}
    assert {"plaso.kiddaland.net", "www.google.com", "ssl.gstatic.com", "wpad.localdomain"} <= queries
    resp = [e for e in dns if e.attrs["is_response"] and e.attrs["query"] == "plaso.kiddaland.net"]
    assert resp and resp[0].attrs["rcode"] == "NOERROR" and resp[0].attrs["answers"]
    assert resp[0].timestamp_desc == Desc.RECEIVED


def test_http(report):
    http = by_type(report, "network:http:request")
    hosts = Counter(e.attrs["host"] for e in http)
    assert hosts["plaso.kiddaland.net"] == 3 and hosts["download.windowsupdate.com"] == 4
    first = min(http, key=lambda e: e.timestamp)
    assert first.attrs["method"] == "GET" and first.attrs["url"] == "http://plaso.kiddaland.net/"
    assert first.attrs["status_code"] == 200
    assert "Firefox/18.0" in first.attrs["user_agent"]


def test_tls(report):
    ch = by_type(report, "network:tls:client_hello")
    assert {e.attrs["sni"] for e in ch if e.attrs["sni"]} == {"www.google.com", "ssl.gstatic.com",
                                                             "lh6.googleusercontent.com"}
    assert all(e.attrs["ja3"] == "85c420ab089dac5025034444789a8fb5" for e in ch if e.attrs["sni"])
    certs = by_type(report, "network:tls:certificate")
    leaf = [e for e in certs if e.attrs["chain_depth"] == 0 and e.attrs["sni"] == "www.google.com"][0]
    assert leaf.attrs["subject"].startswith("CN=www.google.com")
    assert leaf.attrs["issuer"] == "CN=Google Internet Authority,O=Google Inc,C=US"
    assert len(leaf.attrs["sha256"]) == 64 and leaf.attrs["not_before_ns"] < leaf.attrs["not_after_ns"]


def test_file_extraction_hashes(test_pcap, tmp_path):
    out = tmp_path / "files"
    rep = PcapParser(extract_dir=str(out)).analyze(str(test_pcap))
    files = by_type(rep, "network:file")
    assert files
    for e in files:
        data = (out / e.attrs["sha256"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == e.attrs["sha256"] and len(data) == e.attrs["size"]
        assert hashlib.md5(data).hexdigest() == e.attrs["md5"]
    home = [e for e in files if e.attrs["url"] == "http://plaso.kiddaland.net/" and e.attrs["direction"] == "resp"]
    assert home and home[0].attrs["mime"] == "text/html"


def test_deterministic(test_pcap):
    a = PcapParser().analyze(str(test_pcap)).events
    b = PcapParser().analyze(str(test_pcap)).events
    assert [e.to_json() for e in a] == [e.to_json() for e in b]
    assert [e.sort_key() for e in a] == sorted(e.sort_key() for e in a)


def test_pcapng_matches_pcap(test_pcap, tmp_path):
    from scapy.utils import PcapNgWriter, rdpcap

    ng = tmp_path / "test.pcapng"
    w = PcapNgWriter(str(ng))
    for p in rdpcap(str(test_pcap)):
        w.write(p)
    w.close()
    a = PcapParser().analyze(str(test_pcap))
    b = PcapParser().analyze(str(ng))
    assert b.format == "pcapng" and b.packets == a.packets and b.warning_count == 0
    key = lambda e: (e.timestamp, e.data_type, e.message)  # noqa: E731 - offsets differ between formats
    assert sorted(map(key, a.events)) == sorted(map(key, b.events))


def _pcap(linktype: int, packets, nanos=False) -> bytes:
    magic = b"\x4d\x3c\xb2\xa1" if nanos else b"\xd4\xc3\xb2\xa1"
    out = magic + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, linktype)
    for sec, frac, data in packets:
        out += struct.pack("<IIII", sec, frac, len(data), len(data)) + data
    return out


def _udp_dns(q: str) -> bytes:
    d = dpkt.dns.DNS(id=0x1234, qd=[dpkt.dns.DNS.Q(name=q, type=dpkt.dns.DNS_A)])
    u = dpkt.udp.UDP(sport=50000, dport=53, data=bytes(d))
    u.ulen = len(u)
    ip = dpkt.ip.IP(src=bytes([10, 0, 0, 1]), dst=bytes([10, 0, 0, 53]), p=dpkt.ip.IP_PROTO_UDP, data=u)
    ip.len = len(ip)
    return bytes(ip)


def test_raw_ip_nanosecond_capture(tmp_path):
    p = tmp_path / "raw.pcap"
    p.write_bytes(_pcap(101, [(1700000000, 123456789, _udp_dns("evil.example"))], nanos=True))
    rep = PcapParser().analyze(str(p))
    dns = by_type(rep, "network:dns")
    assert len(dns) == 1 and dns[0].timestamp == 1700000000_123456789 and dns[0].attrs["query"] == "evil.example"
    assert rep.flows[0].orig_h == "10.0.0.1" and rep.flows[0].resp_p == 53


def test_truncated_and_corrupt_captures(tmp_path, test_pcap):
    data = test_pcap.read_bytes()
    t = tmp_path / "trunc.pcap"
    t.write_bytes(data[:50_000])
    rep = PcapParser().analyze(str(t))
    assert 0 < rep.packets < 1434 and rep.warning_count >= 1
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(data[:24] + struct.pack("<IIII", 1, 0, 0x7FFFFFFF, 10))
    rep = PcapParser().analyze(str(bad))
    assert rep.packets == 0 and "implausible" in rep.warnings[0]
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a capture at all")
    with pytest.raises(ParserError):
        PcapParser().analyze(str(junk))


def test_parse_contract(test_pcap):
    class P:
        evidence_sha256 = "aa" * 32
        evidence_path = "x.pcap"

    events = list(pcapmod.parse(str(test_pcap), P()))
    assert len(events) == 153 and events[0].evidence_sha256 == "aa" * 32


# --------------------------------------------------------------------------- HTTP / TLS units
def test_http_chunked_gzip_pipelined():
    body = gzip.compress(b"hello world" * 100, mtime=0)
    chunked = b"".join(b"%x\r\n" % len(body[i:i + 50]) + body[i:i + 50] + b"\r\n" for i in range(0, len(body), 50))
    stream = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n" + chunked + b"0\r\n\r\n"
              + b"HTTP/1.1 304 Not Modified\r\n\r\n"
              + b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde")
    msgs = httpp.parse_stream(stream, False, ["GET", "GET", "HEAD"])
    assert [m.status for m in msgs] == [200, 304, 200]
    assert msgs[0].entity == b"hello world" * 100 and msgs[0].body == body
    assert msgs[1].body == b"" and msgs[2].body == b""  # HEAD response has no body
    reqs = httpp.parse_stream(b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabcGET / HTTP/1.0\r\n\r\n", True)
    assert [(r.method, r.uri, r.body) for r in reqs] == [("POST", "/u", b"abc"), ("GET", "/", b"")]


def test_http_decompression_bomb_is_capped(monkeypatch):
    monkeypatch.setattr(httpp, "MAX_DECODED_BODY", 1024)
    bomb = gzip.compress(b"\0" * 1_000_000)
    msgs = httpp.parse_stream(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" % len(bomb) + bomb, False)
    assert len(msgs[0].decoded_body) == 1024 and msgs[0].decode_error == "decoded body exceeds cap"


def test_ja3_grease_filtering():
    exts = struct.pack(">HH", 0x0A0A, 0) + struct.pack(">HH", 10, 6) + struct.pack(">HHH", 4, 0x1A1A, 29) \
        + struct.pack(">HHB", 11, 2, 1) + b"\x00"
    name = b"example.com"
    server_name_list = b"\x00" + struct.pack(">H", len(name)) + name  # host_name entry
    sni = struct.pack(">H", len(server_name_list)) + server_name_list
    exts += struct.pack(">HH", 0, len(sni)) + sni
    body = struct.pack(">H", 0x0303) + b"\0" * 32 + b"\x00" + struct.pack(">H", 6) + struct.pack(">HHH", 0x2A2A, 0x1301, 0xC02F) \
        + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    ch = tls.parse_client_hello(body)
    assert ch is not None and ch.sni == "example.com"
    assert ch.ja3_string == "771,4865-49199,10-11-0,29,0"
    assert len(ch.ja3) == 32


# --------------------------------------------------------------------------- properties
@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.binary(max_size=600), st.sampled_from([0, 1, 12, 101, 113, 228, 229, 276, 9999]))
def test_random_packets_never_crash(tmp_path_factory, payload, linktype):
    p = tmp_path_factory.mktemp("fz") / "f.pcap"
    p.write_bytes(_pcap(linktype, [(1, 2, payload), (1, 3, payload[::-1])]))
    rep = PcapParser().analyze(str(p))
    for e in rep.events:
        e.to_json()


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.binary(min_size=1, max_size=3000))
def test_random_files_only_parsererror(tmp_path_factory, blob):
    p = tmp_path_factory.mktemp("fz") / "f.bin"
    for prefix in (b"", b"\xd4\xc3\xb2\xa1", b"\x0a\x0d\x0d\x0a"):
        p.write_bytes(prefix + blob)
        try:
            PcapParser().analyze(str(p))
        except ParserError:
            pass


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.data())
def test_mutated_corpus_capture_never_crashes(test_pcap, tmp_path_factory, data):
    raw = bytearray(test_pcap.read_bytes()[:60_000])
    for _ in range(data.draw(st.integers(1, 20))):
        raw[data.draw(st.integers(0, len(raw) - 1))] = data.draw(st.integers(0, 255))
    p = tmp_path_factory.mktemp("fz") / "m.pcap"
    p.write_bytes(bytes(raw))
    try:
        PcapParser().analyze(str(p))
    except ParserError:
        pass


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=2000))
def test_protocol_helpers_never_raise(blob):
    httpp.parse_stream(blob, True)
    httpp.parse_stream(blob, False)
    tls.parse_client_hello(blob)
    tls.parse_server_hello(blob)
    for _t, body, _c in tls.iter_handshakes(tls.handshake_bytes(blob)):
        tls.parse_certificates(body)
    tls.describe_certificate(blob)
    httpp.sniff_mime(blob)


def test_capture_reader_ignores_unknown_pcapng_blocks():
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body + struct.pack("<I", 12 + len(shb_body))
    idb_body = struct.pack("<HHI", 101, 0, 65535) + struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)
    idb = struct.pack("<II", 1, 12 + len(idb_body)) + idb_body + struct.pack("<I", 12 + len(idb_body))
    unk = struct.pack("<II", 0xBAD, 16) + b"\0" * 4 + struct.pack("<I", 16)
    pkt = _udp_dns("a.b")
    pad = (-len(pkt)) % 4
    ts = 1_700_000_000_123_456_789
    epb_body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(pkt), len(pkt)) + pkt + b"\0" * pad
    epb = struct.pack("<II", 6, 12 + len(epb_body)) + epb_body + struct.pack("<I", 12 + len(epb_body))
    import io

    warnings = []
    pkts = list(iter_packets(io.BytesIO(shb + idb + unk + epb), warnings.append))
    assert warnings == [] and len(pkts) == 1 and pkts[0].ts_ns == ts and pkts[0].linktype == 101
