"""Zeek adapter tested with a fake ``zeek`` executable placed on PATH (Zeek has no Windows build).

The fake writes JSON and TSV logs like Zeek's ASCII writer, records its argv and environment
keys, and can be told to fail, so the subprocess integration, both log formats, exact timestamp
conversion, credential scrubbing and the native fallback are all exercised.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import textwrap
from decimal import Decimal

import pytest
from hypothesis import given, settings, strategies as st

from veritas.network import zeek as zeekmod
from veritas.network.zeek import ZeekAdapter, ZeekConfig, find_zeek, read_log, zeek_time_ns
from veritas.parsers.base import ParserError, Provenance
from veritas.timeline.schema import Desc

FAKE_ZEEK = textwrap.dedent(r'''
    import json, os, sys
    rec = os.environ.get("FAKE_ZEEK_RECORD")
    if rec:
        with open(rec, "w", encoding="utf-8") as fh:
            json.dump({"argv": sys.argv[1:], "cwd": os.getcwd(), "env": sorted(os.environ)}, fh)
    if os.environ.get("FAKE_ZEEK_FAIL"):
        sys.stderr.write("fatal error: failed to read pcap\n")
        sys.exit(3)
    assert sys.argv[1:3] == ["-C", "-r"], sys.argv
    def jl(name, rows):
        with open(name + ".log", "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
    jl("conn", [
        {"ts": 1374174706.795704, "uid": "CabC1", "id.orig_h": "192.168.1.10", "id.orig_p": 49152,
         "id.resp_h": "93.184.216.34", "id.resp_p": 80, "proto": "tcp", "service": "http",
         "duration": 1.000001, "orig_bytes": 120, "resp_bytes": 5000, "conn_state": "SF",
         "orig_pkts": 6, "resp_pkts": 7, "history": "ShADadFf"},
        {"ts": 1374174707.1, "uid": "CabC2", "id.orig_h": "192.168.1.10", "id.orig_p": 53000,
         "id.resp_h": "8.8.8.8", "id.resp_p": 53, "proto": "udp", "service": "dns"},
    ])
    with open("dns.log", "w", encoding="utf-8") as fh:
        fh.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tdns\n")
        fh.write("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqtype_name\trcode_name\tanswers\n")
        fh.write("#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tstring\tstring\tstring\tvector[string]\n")
        fh.write("1374174707.100000\tCabC2\t192.168.1.10\t53000\t8.8.8.8\t53\tudp\t4660\tevil\\x2dsite.example\tA\tNOERROR\t198.51.100.7,198.51.100.8\n")
        fh.write("1374174707.200000\tCabC3\t192.168.1.10\t53001\t8.8.8.8\t53\tudp\t4661\tnx.example\tA\tNXDOMAIN\t-\n")
        fh.write("garbage line without enough columns\n")
        fh.write("#close\t2013-07-18-19-12-26\n")
    jl("http", [{"ts": 1374174706.9, "uid": "CabC1", "id.orig_h": "192.168.1.10", "id.orig_p": 49152,
                 "id.resp_h": "93.184.216.34", "id.resp_p": 80, "method": "GET", "host": "example.com",
                 "uri": "/payload.exe", "user_agent": "curl/8", "status_code": 200, "resp_fuids": ["FfA1"],
                 "resp_mime_types": ["application/x-dosexec"]}])
    jl("ssl", [{"ts": 1374174708.0, "uid": "CabC4", "id.orig_h": "192.168.1.10", "id.orig_p": 49200,
                "id.resp_h": "142.250.1.1", "id.resp_p": 443, "version": "TLSv12", "server_name": "www.google.com",
                "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "established": True}])
    jl("files", [{"ts": 1374174706.95, "fuid": "FfA1", "conn_uids": ["CabC1"], "source": "HTTP",
                  "mime_type": "application/x-dosexec", "filename": "payload.exe", "seen_bytes": 4096,
                  "total_bytes": 4096, "missing_bytes": 0, "md5": "0" * 32, "sha1": "1" * 40, "sha256": "2" * 64,
                  "tx_hosts": ["93.184.216.34"], "rx_hosts": ["192.168.1.10"]}])
    jl("x509", [{"ts": 1374174708.01, "fingerprint": "ab" * 32, "certificate.subject": "CN=www.google.com",
                 "certificate.issuer": "CN=Google Internet Authority", "certificate.serial": "01",
                 "certificate.not_valid_before": 1372000000.0, "certificate.not_valid_after": 1404000000.0,
                 "san.dns": ["www.google.com"]}])
    jl("weird", [{"ts": 1.0, "name": "ignored"}])
''')


@pytest.fixture
def fake_zeek(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "fake_zeek.py"
    script.write_text(FAKE_ZEEK, encoding="utf-8")
    if os.name == "nt":
        (bindir / "zeek.bat").write_text(f'@"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
    else:
        exe = bindir / "zeek"
        exe.write_text(f"#!{sys.executable}\n" + FAKE_ZEEK, encoding="utf-8")
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.delenv("VERITAS_ZEEK", raising=False)
    record = tmp_path / "record.json"
    monkeypatch.setenv("FAKE_ZEEK_RECORD", str(record))
    pcap = tmp_path / "cap ture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    return {"bindir": bindir, "record": record, "pcap": pcap}


def test_zeek_found_on_path(fake_zeek):
    found = find_zeek()
    assert found and os.path.dirname(found).lower() == str(fake_zeek["bindir"]).lower()


def test_zeek_run_and_mapping(fake_zeek, monkeypatch):
    monkeypatch.setenv("VERITAS_VT_API_KEY", "vt-secret-should-not-leak")
    prov = Provenance(evidence_sha256="11" * 32, evidence_path="net/cap.pcap")
    rep = ZeekAdapter().analyze(str(fake_zeek["pcap"]), prov)
    assert rep.backend == "zeek"
    assert rep.logs == {"conn": 2, "dns": 2, "http": 1, "ssl": 1, "files": 1, "x509": 1}
    assert rep.warning_count == 1 and "columns" in rep.warnings[0]
    rec = json.loads(fake_zeek["record"].read_text(encoding="utf-8"))
    assert rec["argv"][:3] == ["-C", "-r", str(fake_zeek["pcap"].resolve())]
    assert "LogAscii::use_json=T" in rec["argv"] and "frameworks/files/hash-all-files" in rec["argv"]
    assert "VERITAS_VT_API_KEY" not in rec["env"] and "FAKE_ZEEK_RECORD" in rec["env"]
    assert not os.path.exists(rec["cwd"])  # temporary log dir cleaned up

    ev = {e.data_type: [] for e in rep.events}
    for e in rep.events:
        ev[e.data_type].append(e)
    conn = next(e for e in ev["network:conn"] if e.attrs["uid"] == "CabC1")
    assert conn.timestamp == 1374174706_795704000 and conn.timestamp_desc == Desc.START
    assert conn.attrs["duration_ns"] == 1_000_001_000 and conn.attrs["service"] == "http"
    assert conn.evidence_path == "net/cap.pcap" and conn.parser == "zeek"
    dns = {e.attrs["query"]: e for e in ev["network:dns"]}
    assert dns["evil-site.example"].attrs["answers"] == ["198.51.100.7", "198.51.100.8"]
    assert dns["evil-site.example"].timestamp == 1374174707_100000000
    assert dns["nx.example"].attrs["rcode"] == "NXDOMAIN" and dns["nx.example"].attrs["answers"] == []
    http = ev["network:http:request"][0]
    assert http.attrs["url"] == "http://example.com/payload.exe" and http.attrs["status_code"] == 200
    f = ev["network:file"][0]
    assert f.attrs["sha256"] == "2" * 64 and f.attrs["uid"] == "CabC1" and f.attrs["complete"] is True
    assert ev["network:tls:client_hello"][0].attrs["sni"] == "www.google.com"
    cert = ev["network:tls:certificate"][0]
    assert cert.attrs["not_before_ns"] == 1372000000 * 10**9
    for e in rep.events:
        assert "vt-secret" not in e.to_json()
        assert '"zeek_log"' in e.to_json()


def test_zeek_failure_falls_back_to_native(fake_zeek, monkeypatch, corpus):
    monkeypatch.setenv("FAKE_ZEEK_FAIL", "1")
    pcap = corpus / "plaso" / "test.pcap"
    rep = ZeekAdapter().analyze(str(pcap))
    assert rep.backend == "native" and len(rep.events) == 153
    assert any("zeek exited 3" in w for w in rep.warnings)
    with pytest.raises(ParserError):
        ZeekAdapter(ZeekConfig(fallback=False)).analyze(str(pcap))


def test_no_zeek_uses_native(monkeypatch, tmp_path, corpus):
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv("VERITAS_ZEEK", raising=False)
    assert find_zeek() is None
    rep = ZeekAdapter().analyze(str(corpus / "plaso" / "test.pcap"))
    assert rep.backend == "native" and "not found" in rep.warnings[0]
    events = list(zeekmod.parse(str(corpus / "plaso" / "test.pcap"), Provenance(evidence_path="t.pcap")))
    assert len(events) == 153


def test_zeek_time_conversion_is_exact():
    assert zeek_time_ns("1374174706.795704") == 1374174706_795704000
    assert zeek_time_ns(Decimal("0.000000001")) == 1
    assert zeek_time_ns("2013-07-18T19:11:46.795704Z") == 1374174706_795704000
    assert zeek_time_ns("-") is None and zeek_time_ns("nan") is None and zeek_time_ns(1.5) is None


@settings(max_examples=200, deadline=None)
@given(st.lists(st.text(max_size=80), max_size=12), st.booleans())
def test_read_log_never_raises(tmp_path_factory, lines, tsv):
    p = tmp_path_factory.mktemp("z") / "conn.log"
    head = "#separator \\x09\n#fields\tts\tuid\n#types\ttime\tstring\n" if tsv else ""
    p.write_text(head + "\n".join(lines), encoding="utf-8", errors="replace")
    warnings = []
    rows = list(read_log(str(p), warnings.append, 1000))
    a = ZeekAdapter()
    for i, r in enumerate(rows):
        for log in ("conn", "dns", "http", "ssl", "files", "x509"):
            try:
                ev = getattr(a, f"_map_{log}")(r, i)
                ev.to_json()
            except (AttributeError, TypeError):
                pass  # mapping errors are caught per row by parse_log_dir; here we only check reading
