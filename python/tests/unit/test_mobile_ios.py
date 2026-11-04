"""iOS backup directory + standalone iOS database/plist parsers."""
from __future__ import annotations

import os
import plistlib
import shutil
import sqlite3
import tarfile
import zipfile
from collections import Counter
from pathlib import Path

import pytest

from veritas.mobile import ios_backup, ios_db
from veritas.mobile.common import ADDED, ParserError
from veritas.timeline.schema import Desc

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "mobile"
BACKUP = FIX / "ios_backup"


class Prov:
    evidence_sha256 = "b" * 64
    evidence_path = "case/iphone"
    host = None
    user = "examiner"


def _content(domain: str, rel: str) -> Path:
    fid = ios_backup.file_id(domain, rel)
    return BACKUP / fid[:2] / fid


# --------------------------------------------------------------------------- backup directory


def test_backup_summary():
    r = ios_backup.parse_backup(BACKUP, evidence_sha256="b" * 64)
    assert len(r) == 47
    assert Counter(e.data_type for e in r.events) == {
        "ios:backup:file": 24, "ios:photos:asset": 5, "ios:sms:message": 5, "ios:addressbook:contact": 3,
        "ios:callhistory:call": 3, "ios:wifi:known_network": 3, "ios:app:installed": 2, "ios:backup:info": 1,
        "ios:backup:status": 1}
    assert r.warnings == [
        "HomeDomain/Library/Accounts/Accounts3.sqlite: not a SQLite 3 database",
        "HomeDomain/Library/Notes/NoteStore.sqlite: content file "
        + ios_backup.file_id("HomeDomain", "Library/Notes/NoteStore.sqlite") + " missing from backup",
    ]
    assert all(e.host == "Examiner iPhone" for e in r.events)


def test_backup_info_redaction():
    r = ios_backup.parse_backup(BACKUP)
    info = [e for e in r.events if e.data_type == "ios:backup:info"][0]
    assert info.timestamp == 1677748500000000000
    assert "IMEI ***********5678" in info.message and "356789012345678" not in info.message
    assert "serial ********CDEF" in info.message and "9876" in info.message and "123-9876" not in info.message
    assert info.attrs["imei"] == "356789012345678" and info.attrs["phone_number"] == "+1 (555) 123-9876"
    assert info.attrs["pii"] == ["imei", "phone_number", "serial_number", "unique_identifier"]
    assert info.attrs["product_type"] == "iPhone14,2" and info.attrs["product_version"] == "16.3.1"
    status = [e for e in r.events if e.data_type == "ios:backup:status"][0]
    assert status.timestamp == 1677748530000000000 and status.attrs["isfullbackup"] is False
    apps = [e.attrs["bundle_id"] for e in r.events if e.data_type == "ios:app:installed"]
    assert apps == ["com.example.chat", "net.whatsapp.WhatsApp"]


def test_backup_file_events():
    b = ios_backup.IosBackup(BACKUP)
    assert len(b.entries) == 9
    sms = b.lookup("HomeDomain", "Library/SMS/sms.db")
    assert sms.file_id == "3d0d7e5fb2ce288813306e4d4636395e047a3d28" and sms.kind == "file"
    assert sms.metadata["LastModified"] == 1677700000 and sms.metadata["Size"] == _content("HomeDomain", "Library/SMS/sms.db").stat().st_size
    assert b.content_path(sms).endswith(sms.file_id)
    assert b.lookup("HomeDomain", "Library/SMS").kind == "directory"
    assert b.lookup("MediaDomain", "Library/no-metadata").metadata == {}
    assert b.content_path(ios_backup.ManifestEntry("zz", "d", "r", 1)) is None
    r = ios_backup.parse_backup(BACKUP)
    fe = [e for e in r.events if e.data_type == "ios:backup:file" and e.evidence_path == "HomeDomain/Library/SMS/sms.db"]
    assert {e.timestamp_desc: e.timestamp for e in fe} == {
        Desc.MODIFICATION: 1677700000000000000, Desc.CREATION: 1677696400000000000,
        Desc.METADATA_MODIFICATION: 1677700000000000000}
    assert fe[0].attrs["mode"] == "0o100644" and fe[0].attrs["uid"] == 501


def test_backup_without_file_events_and_provenance():
    events = list(ios_backup.parse(BACKUP, Prov(), file_events=False))
    assert len(events) == 23 and all(e.evidence_sha256 == "b" * 64 for e in events)
    assert all(e.user == "examiner" for e in events if e.data_type != "ios:sms:message" or e.user)


def test_backup_archives(tmp_path):
    z = tmp_path / "backup.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../evil.txt", b"x")
        zf.writestr("Backup/", b"")
        for root, _, files in os.walk(BACKUP):
            for f in sorted(files):
                full = Path(root) / f
                zf.write(full, "Backup/UDID/" + full.relative_to(BACKUP).as_posix())
    assert len(list(ios_backup.parse(z, Prov()))) == 47
    assert not (tmp_path / "evil.txt").exists()
    t = tmp_path / "backup.tar"
    with tarfile.open(t, "w") as tf:
        tf.add(BACKUP, arcname="ios_backup")
    assert len(list(ios_backup.parse(t))) == 47
    empty = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty, "w") as zf:
        zf.writestr("readme.txt", b"x")
    with pytest.raises(ParserError, match="does not contain an iOS backup"):
        ios_backup.parse(empty)
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\x00" * 100)
    with pytest.raises(ParserError):
        ios_backup.parse(junk)
    with pytest.raises(ParserError):
        ios_backup.parse(tmp_path / "missing")
    with pytest.raises(ParserError):
        ios_backup.parse(b"bytes")


def test_encrypted_and_invalid_backups(tmp_path):
    with pytest.raises(ParserError, match="encrypted iOS backup"):
        ios_backup.parse(FIX / "ios_backup_encrypted")
    with pytest.raises(ParserError, match="not a backup directory"):
        ios_backup.IosBackup(tmp_path / "nope")
    with pytest.raises(ParserError, match="Manifest.db missing"):
        ios_backup.parse_backup(tmp_path)
    (tmp_path / "Manifest.mbdb").write_bytes(b"mbdb")
    with pytest.raises(ParserError, match="Manifest.mbdb"):
        ios_backup.parse_backup(tmp_path)
    (tmp_path / "Manifest.plist").write_bytes(plistlib.dumps(["not", "a", "dict"]))
    with pytest.raises(ParserError, match="root is not a dictionary"):
        ios_backup.parse_backup(tmp_path)
    (tmp_path / "Manifest.plist").unlink()
    (tmp_path / "Manifest.mbdb").unlink()
    conn = sqlite3.connect(tmp_path / "Manifest.db")
    conn.execute("CREATE TABLE Other (x)")
    conn.commit()
    conn.close()
    with pytest.raises(ParserError, match="no Files table"):
        ios_backup.parse_backup(tmp_path)


def test_decode_file_blob_variants():
    assert ios_backup.decode_file_blob(None) == {}
    assert ios_backup.decode_file_blob(b"junk") == {}
    assert ios_backup.decode_file_blob(plistlib.dumps([1])) == {}
    assert ios_backup.decode_file_blob(plistlib.dumps({"Size": 3})) == {"Size": 3}
    weird = {"$top": {"root": plistlib.UID(9)}, "$objects": ["$null"]}
    assert ios_backup.decode_file_blob(plistlib.dumps(weird, fmt=plistlib.FMT_BINARY)) == {}
    ok = {"$top": {"root": plistlib.UID(1)},
          "$objects": ["$null", {"Size": 5, "Target": plistlib.UID(0), "List": [1], "$class": plistlib.UID(0)}]}
    assert ios_backup.decode_file_blob(plistlib.dumps(ok, fmt=plistlib.FMT_BINARY)) == {"Size": 5, "Target": None}


# --------------------------------------------------------------------------- per-database parsers (synthetic)


def test_sms_db():
    r = ios_db.parse_sms(_content("HomeDomain", "Library/SMS/sms.db"))
    got = [(e.attrs["rowid"], e.timestamp_desc, e.timestamp) for e in r.events]
    assert got == [
        (1, Desc.RECEIVED, 1677664800000000000), (1, "Read Time", 1677664860000000000),
        (2, Desc.SENT, 1677664920000000000), (2, "Delivered Time", 1677664925000000000),
        (3, Desc.RECEIVED, 1677668400000000000)]
    first = r.events[0]
    assert first.attrs["handle"] == "+15551230001" and first.attrs["service"] == "iMessage"
    assert first.attrs["chat_identifier"] == "+15551230001" and first.attrs["is_from_me"] is False
    assert r.events[4].attrs["chat_display_name"] == "Courier" and r.events[4].attrs["service"] == "SMS"
    assert r.events[2].message == "iMessage to +15551230001: On my way"


def test_call_history():
    r = ios_db.parse_call_history(_content("HomeDomain", "Library/CallHistoryDB/CallHistory.storedata"))
    assert [(e.timestamp_desc, e.timestamp) for e in r.events] == [
        (Desc.START, 1677672000500000000), (Desc.END, 1677672125500000000), (Desc.START, 1677675600000000000)]
    assert r.events[0].attrs["direction"] == "outgoing" and r.events[0].attrs["duration_ms"] == 125000
    assert r.events[2].attrs["direction"] == "missed" and r.events[2].attrs["call_type_name"] == "facetime_video"


def test_address_book():
    r = ios_db.parse_address_book(_content("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb"))
    assert [(e.timestamp_desc, e.timestamp) for e in r.events] == [
        (Desc.CREATION, 1578307200000000000), (Desc.MODIFICATION, 1677607200000000000), (Desc.NOT_A_TIME, None)]
    alice = r.events[0]
    assert alice.attrs["phones"] == ["+15551230001"] and alice.attrs["emails"] == ["alice@example.com"]
    assert r.events[2].attrs["organization"] == "Harbor Freight Co" and r.events[2].attrs["phones"] == ["+15559998888"]


def test_photos():
    r = ios_db.parse_photos(_content("CameraRollDomain", "Media/PhotoData/Photos.sqlite"))
    assert [(e.attrs["pk"], e.timestamp_desc, e.timestamp) for e in r.events] == [
        (1, Desc.CREATION, 1677661200250000000), (1, ADDED, 1677661205000000000), (1, Desc.MODIFICATION, 1677661210000000000),
        (2, Desc.CREATION, 1677668400000000000), (2, ADDED, 1677668401000000000)]
    img = r.events[0]
    assert img.attrs["latitude"] == "37.774929" and img.attrs["longitude"] == "-122.419416"
    assert img.attrs["kind_name"] == "photo" and img.attrs["filename"] == "IMG_0001.HEIC"
    assert "latitude" not in r.events[3].attrs and r.events[3].attrs["kind_name"] == "video"


def test_legacy_wifi_plist():
    r = ios_db.parse_wifi_plist(_content("WirelessDomain", "Library/Preferences/com.apple.wifi.plist"))
    assert [(e.attrs["ssid"], e.timestamp_desc, e.timestamp) for e in r.events] == [
        ("CoffeeShop", ios_db.LAST_JOINED, 1677573000000000000),
        ("CoffeeShop", ios_db.JOINED_BY_SYSTEM, 1677657600000000000),
        ("Airport_Free", Desc.NOT_A_TIME, None)]


# --------------------------------------------------------------------------- corpus iOS files


def test_corpus_known_networks(corpus):
    r = ios_db.parse_wifi_plist(corpus / "plaso" / "ios" / "com.apple.wifi.known-networks.plist")
    assert [(e.timestamp_desc, e.timestamp) for e in r.sorted()] == [
        (ios_db.JOINED_BY_USER, 1681566827472469000), (ADDED, 1681566827476017000),
        (ios_db.JOINED_BY_SYSTEM, 1684612503073186000), (Desc.MODIFICATION, 1684612503077004000)]
    e = r.events[0]
    assert e.attrs["ssid"] == "Matt_Foley" and e.attrs["security"] == "WPA2 Personal"
    assert e.attrs["bssid"] == "6a:22:32:98:f4:df" and len(e.attrs["bssids"]) == 9 and e.attrs["channel"] == 161


def test_corpus_mobilebackup_plist(corpus):
    r = ios_db.parse_mobilebackup_plist(corpus / "plaso" / "ios" / "com.apple.MobileBackup.plist")
    assert len(r) == 12
    ev = r.sorted()
    assert ev[0].timestamp == 1681567122481634000 and ev[0].message == "iCloud backup enabled"
    assert ev[-1].timestamp == 1684546855339560000 and ev[-1].attrs["description"] == "Backup succeeded"
    assert sum(1 for e in r.events if e.attrs["field"] == "BackupStateInfo.errors") == 10


def test_corpus_accounts(corpus):
    r = ios_db.parse_accounts(corpus / "plaso" / "ios" / "Accounts3.sqlite")
    assert len(r) == 18
    first = r.events[1]
    assert first.user == "thisisdfir@gmail.com" and first.attrs["owning_bundle_id"] == "com.apple.purplebuddy"
    assert first.timestamp == 1584827262043928000
    ev = r.sorted()
    assert ev[0].timestamp == 1584826791912371000 and ev[-1].timestamp == 1584839489572603000


def test_corpus_datausage_and_netusage(corpus):
    d = ios_db.parse_datausage(corpus / "plaso" / "ios" / "DataUsage.sqlite")
    assert len(d) == 1629
    assert Counter(e.data_type for e in d.events) == {"ios:datausage:process": 742, "ios:datausage:live_usage": 887}
    usage = [e for e in d.events if e.data_type == "ios:datausage:live_usage"][0]
    assert usage.attrs["pk"] == 2 and usage.attrs["wwanin_bytes"] == 1185814689 and usage.timestamp == 1681224315450549000
    n = ios_db.parse_netusage(corpus / "plaso" / "ios" / "netusage.sqlite")
    assert len(n) == 855
    assert Counter(e.data_type for e in n.events) == {"ios:netusage:process": 520, "ios:netusage:live_usage": 335}
    assert n.sorted()[0].timestamp == 1610911417411826000


def test_corpus_notes(corpus):
    r = ios_db.parse_notes(corpus / "plaso" / "ios" / "NoteStore.sqlite")
    assert len(r) == 16
    titles = sorted({e.attrs.get("title") or "" for e in r.events})
    assert "My First Note" in titles and "iOS 14 Locked Note" in titles
    first = r.sorted()[0]
    assert first.timestamp == 1585355808768755000 and first.attrs["title"] == "My First Note"
    assert first.attrs["snippet"] == "This is my first note. Nothing special."
    locked = [e for e in r.events if e.attrs["password_protected"]]
    assert locked and all("(locked)" in e.message for e in locked)


def test_ios_parser_errors(tmp_path):
    db = tmp_path / "x.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE unrelated (x)")
    conn.commit()
    conn.close()
    for fn in (ios_db.parse_sms, ios_db.parse_call_history, ios_db.parse_address_book, ios_db.parse_photos,
               ios_db.parse_accounts, ios_db.parse_datausage, ios_db.parse_notes):
        with pytest.raises(ParserError):
            fn(db)
    for bad in (plistlib.dumps([1]), plistlib.dumps({"x": 1}), b"", b"<!ENTITY x>"):
        with pytest.raises(ParserError):
            ios_db.parse_wifi_plist(bad)
    with pytest.raises(ParserError):
        ios_db.parse_mobilebackup_plist(plistlib.dumps({"x": 1}))
    r = ios_db.parse_mobilebackup_plist(plistlib.dumps({"BackupStateInfo": {"errors": ["x"]}}))
    assert len(r) == 0 and r.warnings == ["MobileBackup plist: no dated entries"]
    assert ios_db.parser_for("a/b/Photos.sqlite") is ios_db.parse_photos and ios_db.parser_for("x") is None


def test_minimal_schemas(tmp_path):
    """Older/variant schemas: ZGENERICASSET, chat_message_join without chat, notes without Z_PRIMARYKEY."""
    db = tmp_path / "p.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE ZGENERICASSET (Z_PK INTEGER PRIMARY KEY, ZFILENAME TEXT, ZDATECREATED FLOAT, ZLATITUDE FLOAT, ZLONGITUDE FLOAT);
        INSERT INTO ZGENERICASSET VALUES (1, 'a.jpg', 700000000.0, 0, 0);
        CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT, date INTEGER, is_from_me INTEGER, handle_id INTEGER);
        INSERT INTO message VALUES (1, 'hi', 0, 1, 5);
        CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
        INSERT INTO chat_message_join VALUES (7, 1);
        CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER PRIMARY KEY, ZTITLE TEXT, ZCREATIONDATE FLOAT, ZMODIFICATIONDATE FLOAT);
        INSERT INTO ZICCLOUDSYNCINGOBJECT VALUES (1, 't', NULL, NULL);
        CREATE TABLE ZPROCESS (Z_PK INTEGER PRIMARY KEY, ZPROCNAME TEXT);
        INSERT INTO ZPROCESS VALUES (1, 'p');
    """)
    conn.commit()
    conn.close()
    p = ios_db.parse_photos(db)
    assert len(p) == 1 and p.events[0].attrs["table"] == "ZGENERICASSET" and "latitude" not in p.events[0].attrs
    s = ios_db.parse_sms(db)
    assert s.events[0].timestamp is None and s.events[0].attrs["chat_id"] == 7
    n = ios_db.parse_notes(db)
    assert n.events[0].timestamp_desc == Desc.NOT_A_TIME and n.events[0].attrs["title"] == "t"
    assert len(ios_db.parse_datausage(db)) == 0


def test_backup_parses_only_files(tmp_path):
    root = tmp_path / "bk"
    shutil.copytree(BACKUP, root)
    os.remove(root / "Info.plist")
    os.remove(root / "Status.plist")
    r = ios_backup.parse_backup(root, file_events=False)
    assert not any(e.data_type in ("ios:backup:info", "ios:backup:status") for e in r.events)
    assert all(e.host is None for e in r.events)
