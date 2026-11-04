"""Hypothesis robustness and determinism for veritas.mobile."""
from __future__ import annotations

import json
import math
import plistlib
from datetime import datetime, timezone
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from veritas.mobile import android_backup, android_db, common, ios_backup, ios_db
from veritas.mobile.common import ParserError

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures" / "mobile"
CORPUS = ROOT.parents[1] / "testdata" / "corpus" / "plaso"
HYP = settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])

BYTE_PARSERS = [
    android_db.parse_mmssms, android_db.parse_contacts2, android_db.parse_calllog, android_db.parse_downloads,
    android_db.parse_webview, android_db.parse_browser, android_db.parse_packages_xml, android_backup.parse_ab,
    ios_db.parse_sms, ios_db.parse_call_history, ios_db.parse_address_book, ios_db.parse_photos,
    ios_db.parse_wifi_plist, ios_db.parse_mobilebackup_plist, ios_db.parse_accounts, ios_db.parse_datausage,
    ios_db.parse_netusage, ios_db.parse_notes,
]


def _sample_files() -> list[bytes]:
    paths = [FIX / "android" / "backup.ab", FIX / "android_pull" / "data" / "system" / "packages.xml",
             *sorted(p for p in (FIX / "ios_backup").rglob("*") if p.is_file())]
    for name in ("android/webview.db", "android/downloads.db", "ios/com.apple.wifi.known-networks.plist",
                 "ios/com.apple.MobileBackup.plist"):
        if (CORPUS / name).is_file():
            paths.append(CORPUS / name)
    return [p.read_bytes() for p in paths]


SAMPLES = _sample_files()


def _run(data: bytes) -> None:
    for fn in BYTE_PARSERS:
        try:
            result = fn(data)
        except ParserError:
            continue
        for e in result:
            json.dumps(e.to_dict())
    ios_backup.decode_file_blob(data)


@HYP
@given(st.binary(max_size=4096))
def test_random_bytes(data):
    _run(data)
    _run(common.SQLITE_MAGIC + data)
    _run(b"ANDROID BACKUP\n5\n1\nnone\n" + data)
    _run(b"bplist00" + data)


@HYP
@given(st.sampled_from(SAMPLES), st.floats(min_value=0, max_value=1), st.binary(min_size=1, max_size=16),
       st.integers(min_value=0, max_value=1 << 20))
def test_truncated_and_corrupted_samples(sample, frac, junk, pos):
    cut = int(len(sample) * frac)
    _run(sample[:cut])
    p = pos % max(len(sample), 1)
    _run(sample[:p] + junk + sample[p + len(junk):])


def test_determinism_two_runs(corpus):
    runs = []
    for _ in range(2):
        out = []
        out.append(ios_backup.parse(FIX / "ios_backup").to_jsonl())
        out.append(android_backup.parse(FIX / "android" / "backup.ab").to_jsonl())
        out.append(android_backup.parse(FIX / "android_pull").to_jsonl())
        for name, fn in sorted(ios_db.FILE_PARSERS.items()):
            for p in sorted((corpus / "plaso" / "ios").iterdir()):
                if p.name.lower() == name:
                    out.append(fn(p).to_jsonl())
        for p in sorted((corpus / "plaso" / "android").iterdir()):
            out.append(android_db.parser_for(p.name)(p).to_jsonl())
        runs.append(out)
    assert runs[0] == runs[1]
    for blob in runs[0]:
        for line in blob.splitlines():
            d = json.loads(line)
            assert list(d["attrs"]) == sorted(d["attrs"])
            assert "float" not in {type(v).__name__ for v in d["attrs"].values()}


def test_common_time_helpers():
    assert common.cocoa_to_ns(0) is None and common.cocoa_to_ns(None) is None
    assert common.cocoa_to_ns(1.5) == 978307201500000000 and common.cocoa_to_ns(2) == 978307202000000000
    assert common.cocoa_to_ns("10") == 978307210000000000 and common.cocoa_to_ns("x") is None
    assert common.cocoa_to_ns(float("nan")) is None and common.cocoa_to_ns("inf") is None
    assert common.cocoa_to_ns(1e300) is None and common.cocoa_to_ns(True) is None and common.cocoa_to_ns([1]) is None
    assert common.ms_to_ns(-5) is None and common.s_to_ns(-1) is None and common.ms_to_ns(1000) == 10**9
    assert common.ios_message_date_to_ns(0) is None
    assert common.dt_to_ns("x") is None
    aware = datetime(2023, 1, 1, tzinfo=timezone.utc)
    assert common.dt_to_ns(aware) == common.dt_to_ns(datetime(2023, 1, 1)) == 1672531200000000000
    assert common.round6(None) is None and common.round6(1) == "1.000000"
    assert common.text(None) is None and common.text(b"\xff") == "�" and common.text(3) == "3"


def test_common_open_errors(tmp_path):
    with pytest.raises(ParserError):
        common.open_sqlite(tmp_path / "missing.db")
    with pytest.raises(ParserError):
        common.open_sqlite(123)
    big = tmp_path / "big.plist"
    big.write_bytes(b"x")
    old = common.MAX_PLIST_BYTES
    try:
        common.MAX_PLIST_BYTES = 0
        with pytest.raises(ParserError, match="larger than"):
            common.load_plist(big)
    finally:
        common.MAX_PLIST_BYTES = old
    wal = bytearray((FIX / "android_pull" / "data" / "data" / "com.android.browser" / "databases" / "browser2.db").read_bytes())
    wal[18:20] = b"\x02\x02"
    assert len(android_db.parse_browser(bytes(wal))) == 4
    assert not math.isnan(0.0)
    assert plistlib.dumps({}) and common.load_plist(plistlib.dumps({"a": 1})) == {"a": 1}
