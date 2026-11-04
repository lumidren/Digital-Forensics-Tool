"""Android database parsers (corpus + synthetic), .ab archives and adb-pull directories."""
from __future__ import annotations

import io
import tarfile
import zlib
from collections import Counter
from pathlib import Path

import pytest

from veritas.mobile import android_backup, android_db
from veritas.mobile.common import ParserError
from veritas.timeline.schema import Desc

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "mobile"
PULL = FIX / "android_pull"
PROV = PULL / "data" / "data"


class Prov:
    evidence_sha256 = "a" * 64
    evidence_path = "case/phone.ab"
    host = "pixel-7"
    user = None


# --------------------------------------------------------------------------- corpus databases


def test_mmssms_corpus(corpus):
    r = android_db.parse_mmssms(corpus / "plaso" / "android" / "mmssms.db")
    assert r.warnings == [] and len(r) == 13
    assert Counter(e.timestamp_desc for e in r.events) == {Desc.SENT: 9, Desc.RECEIVED: 4}
    ev = r.sorted()
    assert ev[0].timestamp == 1383065788038000000 and ev[0].timestamp_desc == Desc.SENT
    assert ev[0].attrs["body"] == "Yo Fred this is my new number." and ev[0].attrs["address"] == "1 555-521-5554"
    assert ev[-1].timestamp == 1383066977250000000
    who = [e for e in r.events if e.attrs["id"] == 4]
    assert {e.timestamp_desc for e in who} == {Desc.RECEIVED, Desc.SENT}
    assert who[0].attrs["type_name"] == "received" and who[0].attrs["body"] == "Who dis??"
    assert all(e.data_type == "android:messaging:sms" for e in r.events)


def test_contacts2_corpus_calls(corpus):
    r = android_db.parse_contacts2(corpus / "plaso" / "android" / "contacts2.db")
    assert len(r) == 5 and r.warnings == []
    starts = [e for e in r.events if e.timestamp_desc == Desc.START]
    assert [e.attrs["type_name"] for e in starts] == ["missed", "outgoing", "incoming"]
    assert starts[0].timestamp == 1383772636690000000 and starts[0].attrs["name"] == "Barney"
    assert starts[0].attrs["geocoded_location"] == "Bedrock"
    ends = [e for e in r.events if e.timestamp_desc == Desc.END]
    assert [e.timestamp for e in ends] == [1383772733283000000 + 126 * 10**9, 1383782616690000000 + 639 * 10**9]


def test_downloads_corpus(corpus):
    r = android_db.parse_downloads(corpus / "plaso" / "android" / "downloads.db")
    assert len(r) == 11
    ev = r.sorted()
    assert ev[0].timestamp == 1668267148279000000
    assert ev[0].attrs["uri"].endswith("IMG_1953.jpg") and ev[0].attrs["notification_package"] == "com.discord"
    assert ev[0].attrs["total_bytes"] == 2149749 and ev[0].attrs["status_name"] == "success"
    assert ev[-1].timestamp == 1670267309761000000 and ev[-1].attrs["status_name"] == "waiting_to_retry"
    assert Counter(e.attrs["status"] for e in r.events) == {200: 4, 495: 6, 194: 1}


def test_webview_corpus(corpus):
    r = android_db.parse_webview(corpus / "plaso" / "android" / "webview.db")
    assert len(r) == 10
    assert Counter(e.data_type for e in r.events) == {"android:webview:cookie": 8, "android:webview:formdata": 2}
    dated = sorted(e.timestamp for e in r.events if e.timestamp is not None)
    assert dated == [1394031884000000000, 1425567767000000000, 1425567768000000000]
    form = [e for e in r.events if e.data_type == "android:webview:formdata"]
    assert form[0].attrs["value"] == "hanklivingston11@gmail.com" and form[0].attrs["pii"] is True
    assert form[0].attrs["url"].startswith("https://login.skype.com/account/password-reset-request")
    login = [e for e in r.events if e.attrs.get("name") == "skype-login"][0]
    assert login.attrs["secure"] is True and login.timestamp_desc == Desc.NOT_A_TIME


# --------------------------------------------------------------------------- synthetic databases


def test_synthetic_mmssms_with_mms():
    r = android_db.parse_mmssms(PROV / "com.android.providers.telephony" / "databases" / "mmssms.db")
    mms = [e for e in r.events if e.data_type == "android:messaging:mms"]
    assert len(mms) == 2
    assert mms[0].timestamp == 1677665000000000000 and mms[0].timestamp_desc == Desc.RECEIVED
    assert mms[0].attrs["body"] == "Look at this" and mms[0].attrs["addresses"] == ["+15551230001"]
    assert [p["content_type"] for p in mms[0].attrs["parts"]] == ["application/smil", "text/plain", "image/jpeg"]
    assert mms[1].timestamp_desc == Desc.SENT and mms[1].attrs["msg_box_name"] == "sent"
    draft = [e for e in r.events if e.attrs.get("type_name") == "draft"]
    assert draft[0].timestamp_desc == Desc.CREATION


def test_synthetic_calllog_and_contacts():
    calls = android_db.parse_calllog(PROV / "com.android.providers.contacts" / "databases" / "calllog.db")
    assert [(e.timestamp, e.timestamp_desc) for e in calls.events] == [
        (1677664800000000000, Desc.START), (1677664860000000000, Desc.END), (1677668400000000000, Desc.START)]
    assert calls.events[2].attrs["type_name"] == "missed"
    c = android_db.parse_contacts2(PROV / "com.android.providers.contacts" / "databases" / "contacts2.db")
    assert len(c) == 2
    alice, bob = c.events
    assert alice.data_type == "android:contacts:contact" and alice.timestamp == 1677664800000000000
    assert alice.attrs["phones"] == ["+15551230001"] and alice.attrs["emails"] == ["alice@example.com"]
    assert alice.attrs["given_name"] == "Alice" and alice.attrs["account_type"] == "com.google"
    assert bob.attrs["display_name"] == "Bob Builder" and bob.timestamp is None


def test_browser_and_packages():
    b = android_db.parse_browser(PROV / "com.android.browser" / "databases" / "browser2.db")
    assert Counter(e.data_type for e in b.events) == {"android:browser:history": 3, "android:browser:bookmark": 1}
    first = b.sorted()[0]
    assert first.timestamp == 1677500000000000000 and first.attrs["url"] == "https://docs.example/"
    p = android_db.parse_packages_xml(PULL / "data" / "system" / "packages.xml")
    assert len(p) == 3
    inst = [e for e in p.events if e.timestamp_desc == Desc.INSTALLATION][0]
    assert inst.timestamp == 1677000000000000000 and inst.attrs["package"] == "com.example.chat"
    assert inst.attrs["permissions"] == ["android.permission.CAMERA", "android.permission.READ_SMS"]
    assert inst.attrs["installer"] == "com.android.vending"
    upd = [e for e in p.events if e.timestamp_desc == Desc.MODIFICATION][0]
    assert upd.timestamp == 1677600000000000000
    settings_pkg = [e for e in p.events if e.attrs["package"] == "com.android.settings"][0]
    assert settings_pkg.timestamp is None and settings_pkg.attrs["user_id"] == "1000"


def test_packages_xml_errors():
    for bad in (b"ABX\x00binary", b"<!DOCTYPE x [<!ENTITY a 'b'>]><packages/>", b"<packages>", b"<other/>"):
        with pytest.raises(ParserError):
            android_db.parse_packages_xml(bad)
    r = android_db.parse_packages_xml(b'<packages><package name="a" it="zz" /></packages>')
    assert r.events[0].timestamp is None


def test_db_parsers_reject_wrong_schema(tmp_path):
    import sqlite3

    db = tmp_path / "other.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE unrelated (x)")
    conn.commit()
    conn.close()
    for fn in (android_db.parse_mmssms, android_db.parse_contacts2, android_db.parse_calllog,
               android_db.parse_downloads, android_db.parse_webview, android_db.parse_browser):
        with pytest.raises(ParserError):
            fn(db)
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, display_name TEXT)")
    conn.execute("INSERT INTO raw_contacts VALUES (1, 'x')")
    conn.execute("CREATE TABLE password (_id INTEGER PRIMARY KEY, host TEXT, username TEXT, password TEXT)")
    conn.execute("INSERT INTO password VALUES (1, 'h', 'u', 'secret')")
    conn.commit()
    conn.close()
    r = android_db.parse_contacts2(db)
    assert r.warnings == ["contacts2.db: raw_contacts without data/mimetypes tables"] and len(r) == 0
    w = android_db.parse_webview(db)
    assert w.events[0].data_type == "android:webview:credential"
    assert w.events[0].attrs["has_password"] is True and "secret" not in w.events[0].to_json()
    assert android_db.parser_for("X/MMSSMS.DB") is android_db.parse_mmssms and android_db.parser_for("a.txt") is None


# --------------------------------------------------------------------------- .ab archives


def test_ab_compressed_backup():
    events = list(android_backup.parse(FIX / "android" / "backup.ab", Prov()))
    assert len(events) == 26
    assert Counter(e.data_type for e in events) == {
        "android:messaging:sms": 13, "android:event:call": 5, "android:backup:file": 5,
        "android:app:package": 2, "android:backup:header": 1}
    header = [e for e in events if e.data_type == "android:backup:header"][0]
    assert header.attrs == {"compressed": True, "encryption": "none", "version": 5}
    files = [e for e in events if e.data_type == "android:backup:file"]
    assert all(e.timestamp == 1700000000000000000 for e in files)
    assert files[0].attrs["package"] in {"com.android.providers.telephony", "com.android.providers.contacts"}
    sms = [e for e in events if e.data_type == "android:messaging:sms"]
    assert sms[0].evidence_path == "case/phone.ab!apps/com.android.providers.telephony/db/mmssms.db"
    assert all(e.evidence_sha256 == "a" * 64 and e.host == "pixel-7" for e in events)
    apps = sorted(e.attrs["package"] for e in events if e.data_type == "android:app:package")
    assert apps == ["com.android.providers.contacts", "com.android.providers.telephony"]


def test_ab_uncompressed_and_header_errors():
    r = android_backup.parse_ab(FIX / "android" / "backup_uncompressed.ab", file_events=False)
    assert len(r) == 15 and r.events[0].attrs["compressed"] is False
    with pytest.raises(ParserError, match="encrypted Android backup"):
        android_backup.parse(FIX / "android" / "backup_encrypted.ab")
    for bad in (b"", b"NOT A BACKUP\n", b"ANDROID BACKUP\n5\n", b"ANDROID BACKUP\nx\n1\nnone\n",
                b"ANDROID BACKUP\n99\n1\nnone\n", b"ANDROID BACKUP\n5\n7\nnone\n", b"ANDROID BACKUP\n5\n1\nnone\n",
                b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(b"\x00" * 1024)):
        with pytest.raises(ParserError):
            android_backup.parse_ab(bad)
    with pytest.raises(ParserError):
        android_backup.parse_ab(Path("missing.ab"))


def test_ab_truncated_stream_is_warning():
    data = (FIX / "android" / "backup.ab").read_bytes()
    r = android_backup.parse_ab(data[: len(data) // 2])
    assert r.warning_count >= 1 and len(r) >= 2


def test_ab_member_parse_error_is_warning():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, payload in (("apps/x/db/mmssms.db", b"junk" * 200), ("apps/x/f/other.bin", b"1")):
            ti = tarfile.TarInfo(name)
            ti.size = len(payload)
            tar.addfile(ti, io.BytesIO(payload))
    r = android_backup.parse_ab(b"ANDROID BACKUP\n5\n0\nnone\n" + buf.getvalue())
    assert r.warnings == ["apps/x/db/mmssms.db: not a SQLite 3 database"]
    assert [e.attrs.get("path") for e in r.events if e.data_type == "android:backup:file"] == [
        "apps/x/db/mmssms.db", "apps/x/f/other.bin"]


# --------------------------------------------------------------------------- adb pull directory


def test_pull_directory_mode():
    r = android_backup.parse(PULL)
    assert r.warnings == ["data/data/com.broken/databases/webview.db: not a SQLite 3 database"]
    assert Counter(e.data_type for e in r.events) == {
        "android:download": 11, "android:browser:history": 3, "android:event:call": 3, "android:messaging:sms": 3,
        "android:app:package": 3, "android:contacts:contact": 2, "android:messaging:mms": 2,
        "android:browser:bookmark": 1}
    paths = {e.evidence_path for e in r.events}
    assert "data/system/packages.xml" in paths
    assert "data/data/com.android.providers.downloads/databases/downloads.db" in paths


def test_pull_directory_errors(tmp_path):
    with pytest.raises(ParserError):
        android_backup.parse_directory(tmp_path)
    with pytest.raises(ParserError):
        android_backup.parse_directory(tmp_path / "nope")
