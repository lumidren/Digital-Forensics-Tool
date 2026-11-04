"""Cross-cutting parser properties: robustness (hypothesis), determinism, JSON safety, registry."""
from __future__ import annotations

import gzip
import io
import json
import struct
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from veritas.parsers import fsevents, registry
from veritas.parsers.base import MAX_STRING, ParserError, Provenance, read_head
from veritas.timeline.schema import write_jsonl

# parser name -> (corpus sample relative to testdata/corpus/plaso or None, file name used for fuzzing)
SAMPLES: dict[str, tuple[str | None, str]] = {
    "pst": ("nromanoff@stark-research-labs.com.pst", "mail.pst"),
    "srum": ("SRUDB.dat", "SRUDB.dat"),
    "msiecf": ("msiecf/nfury_index.dat", "index.dat"),
    "msie_webcache": ("msiecf/WebCacheV01.dat", "WebCacheV01.dat"),
    "recycle_bin": ("recycler/$I103S5F.jpg", "$IABC123.jpg"),
    "recycle_bin_info2": ("recycler/INFO2", "INFO2"),
    "windefender_history": ("windefender_history/6AFE33A0-19BA-4FFF-892F-B700539D7D63", "6AFE33A0-19BA-4FFF-892F-B700539D7D63"),
    "windefender_mplog": (None, "MPLog-20230101-000000.log"),
    "ooxml": ("Document.docx", "doc.docx"),
    "olecf_summary": ("Document.doc", "doc.doc"),
    "asl_log": ("2019.09.26.asl", "2019.09.26.asl"),
    "bsm_log": ("apple.bsm", "audit.bsm"),
    "fseventsd": ("fsevents/fsevents-00000000001a0b79", "00000000001a0b79"),
    "utmp": ("utmp/utmp", "wtmp"),
    "utmpx_macos": ("utmpx_mac", "utmpx"),
    "wmi_persistence": (None, "OBJECTS.DATA"),
    "chromium_history": ("chrome/History", "History"),
    "chromium_cookies": ("chrome/Cookies-68.0.3440.106", "Cookies"),
    "chromium_webdata": ("chrome/Web Data", "Web Data"),
    "chromium_login_data": (None, "Login Data"),
    "firefox_places": ("firefox/places118.sqlite", "places.sqlite"),
    "firefox_downloads": ("firefox/downloads.sqlite", "downloads.sqlite"),
    "firefox_cookies": ("firefox/firefox_10_cookies.sqlite", "cookies.sqlite"),
    "windows_timeline": ("windows/ActivitiesCache.db", "ActivitiesCache.db"),
    "knowledgec": ("macos/knowledgec-10.14.db", "knowledgeC.db"),
    "ls_quarantine": ("sqlite/quarantine.db", "com.apple.LaunchServices.QuarantineEventsV2"),
    "macos_tcc": ("macos/TCC-test.db", "TCC.db"),
    "macos_appusage": ("macos/application_usage.sqlite", "application_usage.sqlite"),
    "macos_notification_center": ("mac_notificationcenter.db", "db"),
    "imessage": ("sqlite/imessage_chat.db", "chat.db"),
    "launchd_plist": ("plist/launchd.minimal.plist", "com.x.plist"),
    "macos_background_items": ("backgrounditems.btm", "backgrounditems.btm"),
    "macos_unified_log_json": (None, "log.ndjson"),
    "macos_logarchive": (None, "x.tracev3"),
    "powershell_transcript": ("powershell_transcript.txt", "PowerShell_transcript.txt"),
    "powershell_history": (None, "ConsoleHost_history.txt"),
    "setupapi": ("setupapi.dev.log", "setupapi.dev.log"),
    "winfirewall": ("windows_firewall.log", "pfirewall.log"),
    "auditd": ("audit.log", "audit.log"),
    "apache_access": ("apache_access.log", "access.log"),
    "dpkg": ("dpkg.log", "dpkg.log"),
    "apt_history": ("apt_history.log", "history.log"),
    "dnf_yum": (None, "dnf.log"),
    "santa": ("santa.log", "santa.log"),
    "macos_wifi": ("wifi.log", "wifi.log"),
    "mac_appfirewall_log": ("appfirewall.log", "appfirewall.log"),
    "macos_launchd_log": ("macos_launchd.log", "launchd.log"),
    "bash_history": ("bash_history", ".bash_history"),
    "zsh_extended_history": ("zsh_extended_history.txt", ".zsh_history"),
    "fish_history": ("fish_history", "fish_history"),
    "ssh_authorized_keys": (None, "authorized_keys"),
    "ssh_known_hosts": (None, "known_hosts"),
    "sshd_config": (None, "sshd_config"),
    "ssh_client_config": (None, "config"),
    "systemd_unit": (None, "x.service"),
    "mbox": (None, "inbox.mbox"),
    "crontab": (None, "crontab"),
    "syslog": ("syslog/syslog", "syslog"),
}
BIG = 4 * 1024 * 1024
CORPUS = Path(__file__).resolve().parents[3] / "testdata" / "corpus" / "plaso"
HAVE_CORPUS = CORPUS.is_dir()
FUZZ = settings(max_examples=12, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def test_every_registered_parser_has_a_fuzz_target():
    assert set(registry.parser_names()) == set(SAMPLES)


def _run_bytes(name: str, fname: str, data: bytes) -> None:
    """Parse ``data`` with parser ``name``; only ParserError may escape."""
    with tempfile.TemporaryDirectory() as d:
        sub = Path(d) / "x" / ".ssh" if fname == "config" else Path(d) / "x"
        sub.mkdir(parents=True)
        path = sub / fname
        path.write_bytes(data)
        parser = registry.get(name)()
        try:
            for _ in parser.parse(str(path), Provenance(evidence_path=str(path))):
                pass
        except ParserError:
            pass


@pytest.mark.parametrize("name", sorted(SAMPLES))
@FUZZ
@given(data=st.binary(min_size=0, max_size=2048))
def test_random_bytes_only_raise_parser_error(name, data):
    _run_bytes(name, SAMPLES[name][1], data)


@pytest.mark.parametrize("name", sorted(SAMPLES))
@FUZZ
@given(prefix=st.sampled_from([b"SQLite format 3\x00", b"\x1f\x8b\x08\x00", b"PK\x03\x04", b"bplist00", b"!BDN",
                               b"ASL DB\x00\x00\x00\x00\x00\x00", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"\x14\x00\x00\x00\x40\x0b",
                               b"1SLD", b"utmpx-1.00\x00", b"type=SYSCALL msg=audit(1.1:1): ", b"[\n", b"{\"eventMessage\": "]),
       data=st.binary(min_size=0, max_size=1024))
def test_magic_prefixed_garbage_only_raises_parser_error(name, prefix, data):
    _run_bytes(name, SAMPLES[name][1], prefix + data)


SAMPLED = sorted(n for n, (rel, _) in SAMPLES.items() if rel)


@pytest.mark.skipif(not HAVE_CORPUS, reason="corpus not present")
@pytest.mark.parametrize("name", SAMPLED)
@FUZZ
@given(frac=st.floats(min_value=0.0, max_value=1.0, allow_nan=False))
def test_truncated_samples_only_raise_parser_error(name, frac):
    rel, fname = SAMPLES[name]
    raw = (CORPUS / rel).read_bytes()
    raw = raw[:BIG]
    _run_bytes(name, fname, raw[: int(len(raw) * frac)])


@pytest.mark.skipif(not HAVE_CORPUS, reason="corpus not present")
@pytest.mark.parametrize("name", [n for n in SAMPLED if (CORPUS / SAMPLES[n][0]).stat().st_size <= 1024 * 1024]
                         if HAVE_CORPUS else [])
@FUZZ
@given(flips=st.lists(st.tuples(st.floats(min_value=0, max_value=0.999), st.integers(1, 255)), min_size=1, max_size=16))
def test_bitflipped_samples_only_raise_parser_error(name, flips):
    rel, fname = SAMPLES[name]
    raw = bytearray((CORPUS / rel).read_bytes())
    for pos, x in flips:
        raw[int(pos * len(raw))] ^= x
    _run_bytes(name, fname, bytes(raw))


def _jsonl(name: str, path: Path) -> str:
    buf = io.StringIO()
    parser = registry.get(name)()
    write_jsonl(parser.parse(str(path), Provenance(evidence_path=path.name, evidence_sha256="ab" * 32, year_hint=2020)), buf)
    return buf.getvalue()


def _assert_json_safe(value, path="attrs"):
    if isinstance(value, dict):
        assert list(value) == sorted(value), f"{path}: keys not sorted"
        for k, v in value.items():
            assert isinstance(k, str)
            _assert_json_safe(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _assert_json_safe(v, f"{path}[{i}]")
    else:
        assert value is None or isinstance(value, (str, int, bool)), f"{path}: {type(value).__name__}"
        if isinstance(value, str):
            assert len(value) <= MAX_STRING


@pytest.mark.skipif(not HAVE_CORPUS, reason="corpus not present")
@pytest.mark.parametrize("name", SAMPLED)
def test_deterministic_and_json_safe(name):
    path = CORPUS / SAMPLES[name][0]
    first = _jsonl(name, path)
    assert first == _jsonl(name, path)
    lines = [ln for ln in first.split("\n") if ln]  # not splitlines(): U+2028 may appear inside strings
    assert lines, f"{name} produced no events"
    for line in lines[:5000]:
        d = json.loads(line)
        assert isinstance(d["timestamp"], int) or d["timestamp"] is None
        assert d["parser"] == name and d["evidence_sha256"] == "ab" * 32
        _assert_json_safe(d["attrs"])


@pytest.mark.skipif(not HAVE_CORPUS, reason="corpus not present")
@pytest.mark.parametrize("name", SAMPLED)
def test_registry_selects_expected_parser(name):
    rel = SAMPLES[name][0]
    path = CORPUS / rel
    if name == "launchd_plist":
        pytest.skip("matched by content only inside LaunchAgents/LaunchDaemons or with Program keys")
    chosen = registry.select(str(path), read_head(str(path)))
    assert chosen is not None and chosen.name == name


@pytest.mark.skipif(not HAVE_CORPUS, reason="corpus not present")
def test_parse_auto(corpus):
    ev = list(registry.parse_auto(str(corpus / "plaso/dpkg.log"), Provenance(evidence_sha256="1" * 64, evidence_path="dpkg.log")))
    assert len(ev) == 4 and ev[0].parser == "dpkg" and ev[0].evidence_sha256 == "1" * 64
    with pytest.raises(ParserError):
        list(registry.parse_auto(str(corpus / "plaso/test_pe.exe"), Provenance()))


def test_fsevents_dls2_synthetic(tmp_path):
    recs = b"/private/tmp/x\x00" + struct.pack("<QIQ", 77, 0x00800011, 123456)
    page = b"2SLD" + b"\x00" * 4 + struct.pack("<I", 12 + len(recs)) + recs
    f = tmp_path / "00000000000000ff"
    f.write_bytes(gzip.compress(page))
    ev = list(fsevents.FseventsParser().parse(str(f), Provenance()))
    assert len(ev) == 1
    a = ev[0].attrs
    assert (a["path"], a["event_identifier"], a["node_identifier"], a["format_version"]) == ("/private/tmp/x", 77, 123456, 2)
    assert a["flag_names"] == ["Created", "Modified", "IsFile"]
