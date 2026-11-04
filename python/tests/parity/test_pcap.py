"""Parity: native PCAP parser vs scapy (independent reader and dissectors).

Compared per sample: packet count, per-packet timestamp (exact ns) and captured length, the set of
L4 flows (unordered 5-tuples), DNS query names and HTTP request lines.
Results are written to parity/results/pcap.json (format: parity/README.md).
"""
from __future__ import annotations

import io
import json
from collections import Counter
from decimal import Decimal
from pathlib import Path

import pytest

from veritas.network.capture import iter_packets
from veritas.network.pcap import PcapParser

pytestmark = pytest.mark.parity
REPO = Path(__file__).resolve().parents[3]
RESULTS = REPO / "parity" / "results" / "pcap.json"
SAMPLES = ["plaso/test.pcap"]


def _scapy_view(path: Path) -> dict:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw
    from scapy.utils import rdpcap

    pkts = rdpcap(str(path))
    ts, lens, flows, dns, http = [], [], set(), Counter(), Counter()
    for p in pkts:
        ts.append(int(Decimal(str(p.time)) * 1_000_000_000))
        lens.append(len(bytes(p)))
        ip = p.getlayer(IP) or p.getlayer(IPv6)
        if ip is None:
            continue
        if IP in p and (p[IP].frag or p[IP].flags.MF and p[IP].frag):
            continue
        for l4, name in ((TCP, "tcp"), (UDP, "udp")):
            if l4 in p:
                a, b = (ip.src, p[l4].sport), (ip.dst, p[l4].dport)
                flows.add((name,) + tuple(sorted([a, b])))
                if name == "udp" and DNS in p and p[DNS].qd is not None and not p[DNS].qr:
                    q = p[DNS].qd
                    for i in range(p[DNS].qdcount):
                        layer = q[i] if hasattr(q, "__getitem__") else q
                        if isinstance(layer, DNSQR):
                            dns[layer.qname.decode("ascii", "replace").rstrip(".")] += 1
                if name == "tcp" and Raw in p:
                    first = bytes(p[Raw].load).split(b"\r\n", 1)[0]
                    if first.split(b" ", 1)[0] in (b"GET", b"POST", b"HEAD", b"PUT"):
                        http[first.decode("latin-1")] += 1
    return {"count": len(pkts), "ts": ts, "lens": lens, "flows": flows, "dns": dns, "http": http}


def _ours(path: Path) -> dict:
    with open(path, "rb") as fh:
        raw = list(iter_packets(io.BytesIO(fh.read()), lambda m: None))
    rep = PcapParser().analyze(str(path))
    flows = {(f.proto,) + tuple(sorted([(f.orig_h, f.orig_p), (f.resp_h, f.resp_p)]))
             for f in rep.flows if f.proto in ("tcp", "udp")}
    dns = Counter(e.attrs["query"] for e in rep.events if e.data_type == "network:dns" and not e.attrs["is_response"]
                  and e.attrs["proto"] == "udp" and 53 in (e.attrs["orig_p"], e.attrs["resp_p"]))
    http = Counter(f"{e.attrs['method']} {e.attrs['uri']} HTTP/{e.attrs['version']}" for e in rep.events
                   if e.data_type == "network:http:request")
    return {"count": rep.packets, "ts": [p.ts_ns for p in raw], "lens": [len(p.data) for p in raw],
            "flows": flows, "dns": dns, "http": http}


def test_pcap_parity_vs_scapy(corpus):
    fields: dict[str, dict[str, int]] = {}
    records_ours = records_ref = 0
    notes = []
    for rel in SAMPLES:
        path = corpus / rel
        if not path.is_file():
            pytest.skip(f"{rel} not in corpus")
        ours, ref = _ours(path), _scapy_view(path)
        records_ours += ours["count"]
        records_ref += ref["count"]

        def agree(name, a, b):
            f = fields.setdefault(name, {"agree": 0, "total": 0})
            f["total"] += 1
            f["agree"] += int(a == b)

        agree("packet_count", ours["count"], ref["count"])
        for a, b in zip(ours["ts"], ref["ts"]):
            agree("timestamp_ns", a, b)
        for a, b in zip(ours["lens"], ref["lens"]):
            agree("captured_length", a, b)
        for fl in ref["flows"] | ours["flows"]:
            agree("flows_5tuple", fl in ours["flows"], fl in ref["flows"])
        for q in set(ref["dns"]) | set(ours["dns"]):
            agree("dns_query_names", ours["dns"][q], ref["dns"][q])
        for line in set(ref["http"]) | set(ours["http"]):
            agree("http_request_lines", ours["http"][line], ref["http"][line])
        missing = sorted(set(ref["http"]) - set(ours["http"]))
        if missing:
            notes.append(f"{rel}: HTTP requests seen by scapy only: {missing[:5]}")
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({
        "parser": "pcap", "reference": "scapy " + __import__("scapy").VERSION, "samples": SAMPLES,
        "records_ours": records_ours, "records_reference": records_ref, "fields": fields,
        "notes": "; ".join(notes) or ("DNS compared on port 53 only: we also decode LLMNR (5355) and mDNS (5353) as DNS, scapy "
                                    "dissects them as separate layers; HTTP request lines: ours from reassembled streams"),
    }, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    for name, f in fields.items():
        assert f["agree"] == f["total"], (name, f)
