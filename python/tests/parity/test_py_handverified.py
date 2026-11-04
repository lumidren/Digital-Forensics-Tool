"""Parity for parsers plaso cannot check in-process: compared against libyal (pypff) raw reads,
the Python standard library, or expectations derived independently from the raw bytes/text.

Results: parity/results/py_pst.json, py_syslog_traditional.json, py_auditd.json, py_mbox.json,
py_wmi_persistence.json (format: parity/README.md).
"""
from __future__ import annotations

import calendar
import email.utils
import json
import mailbox
import re
from collections import Counter
from pathlib import Path

import pytest

from veritas.parsers import auditd, email_pst, mbox, syslog, wmi
from veritas.parsers.base import Provenance
from veritas.timeline.schema import NS, filetime_to_ns

pytestmark = pytest.mark.parity
REPO = Path(__file__).resolve().parents[3]
RESULTS = REPO / "parity" / "results"
PLASO = REPO / "testdata" / "corpus" / "plaso"


def _agree(a, b):
    ca, cb = Counter(a), Counter(b)
    return {"agree": sum(min(ca[k], cb[k]) for k in ca), "total": max(sum(ca.values()), sum(cb.values()))}


def _write(name, summary):
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"py_{name}.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _need(path: Path):
    if not path.exists():
        pytest.skip(f"{path} not present")


def test_pst_vs_pypff_raw_walk():
    pypff = pytest.importorskip("pypff")
    path = PLASO / "nromanoff@stark-research-labs.com.pst"
    _need(path)
    ref_msgs = []

    def walk(folder):
        for i in range(folder.number_of_sub_messages):
            m = folder.get_sub_message(i)
            get = getattr(m, "get_delivery_time_as_integer", None)
            ref_msgs.append({"subject": getattr(m, "subject", None) or "",
                             "delivery": filetime_to_ns(get()) if get and get() else None})
        for j in range(folder.number_of_sub_folders):
            walk(folder.get_sub_folder(j))

    with open(path, "rb") as fh:
        f = pypff.file()
        f.open_file_object(fh)
        walk(f.get_root_folder())
        f.close()
    ev = list(email_pst.PstParser().parse(str(path), Provenance()))
    records = {}
    for e in ev:
        records.setdefault(e.offset, e)
    ours_delivery = [e.timestamp for e in ev if e.timestamp_desc == "Received Time"]
    fields = {"delivery_time": _agree(ours_delivery, [m["delivery"] for m in ref_msgs if m["delivery"]]),
              "subject": _agree([r.attrs["subject"] for r in records.values()], [m["subject"] for m in ref_msgs])}
    _write("pst", {"parser": "py_pst", "reference": f"libpff-python {pypff.get_version()} (independent folder walk)",
                   "samples": ["plaso/nromanoff@stark-research-labs.com.pst"], "records_ours": len(records),
                   "records_reference": len(ref_msgs), "fields": fields,
                   "notes": "plaso has no PST parser; reference is a direct pypff walk of every folder/message."})
    assert len(records) == len(ref_msgs) == 544
    for v in fields.values():
        assert v["agree"] == v["total"]


BSD_HEADER = re.compile(r"^(?:<\d+>)?(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d+))?[ :]")


def test_syslog_traditional_vs_raw_text():
    samples = ["syslog/syslog", "syslog/syslog_ssh.log", "syslog/syslog_cron.log", "syslog/syslog_osx",
               "syslog/syslog_cron_debian.log", "syslog/syslog_crond.log", "syslog/syslog_sshd_session.log",
               "syslog/syslog_sudo_traditional.log"]
    months = {m: i for i, m in enumerate(calendar.month_abbr) if m}
    ours_t, ref_t, n_ours, n_ref = [], [], 0, 0
    for s in samples:
        path = PLASO / s
        _need(path)
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = BSD_HEADER.match(line)
            if m and m.group("mon") in months:
                frac = (m.group("frac") or "")[:6].ljust(6, "0")
                ref_t.append((months[m.group("mon")], int(m.group("day")), m.group("time"), frac))
        ev = [e for e in syslog.SyslogParser().parse(str(path), Provenance(year_hint=2012))
              if e.attrs.get("line_format") == "bsd"]  # ISO/RFC 5424 lines are covered by test_py_plaso
        n_ours += len(ev)
        for e in ev:
            if e.timestamp is None:
                continue
            from datetime import datetime, timezone

            dt = datetime.fromtimestamp(e.timestamp // NS, tz=timezone.utc)
            ours_t.append((dt.month, dt.day, dt.strftime("%H:%M:%S"), f"{(e.timestamp % NS) // 1000:06d}"))
    n_ref = len(ref_t)
    fields = {"timestamps_month_to_us": _agree(ours_t, ref_t)}
    _write("syslog_traditional", {
        "parser": "py_syslog_traditional", "reference": "raw text (independent header regex), year-agnostic",
        "samples": [f"plaso/{s}" for s in samples], "records_ours": n_ours, "records_reference": n_ref, "fields": fields,
        "notes": "plaso resolves BSD syslog years at timeline time (date-less log helper), so it cannot be compared "
                 "in-process. Reference = every line starting with a BSD timestamp."})
    assert fields["timestamps_month_to_us"]["agree"] >= 0.97 * fields["timestamps_month_to_us"]["total"]


AUDIT_HDR = re.compile(r"msg=audit\((\d+)\.(\d+):(\d+)\)")


def test_auditd_vs_raw_serials():
    samples = ["audit.log", "audit_corrupted.log"]
    ours, ref = [], []
    for s in samples:
        path = PLASO / s
        _need(path)
        seen = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = AUDIT_HDR.search(line)
            if m:
                seen.setdefault(int(m.group(3)), int(m.group(1)) * NS + int(m.group(2).ljust(3, "0")) * 1_000_000)
        ref.extend(sorted(seen.items()))
        ours.extend((e.attrs["serial"], e.timestamp) for e in auditd.AuditdParser().parse(str(path), Provenance()))
    fields = {"serial_and_time": _agree(ours, ref)}
    _write("auditd", {"parser": "py_auditd", "reference": "raw text: distinct msg=audit(sec.ms:serial) headers",
                      "samples": [f"plaso/{s}" for s in samples], "records_ours": len(ours), "records_reference": len(ref),
                      "fields": fields, "notes": "plaso has no auditd parser."})
    assert fields["serial_and_time"]["agree"] == fields["serial_and_time"]["total"] == 17


MBOX = (b"From a@x Mon Jan 15 10:00:00 2024\nFrom: A <a@x>\nSubject: one\nDate: Mon, 15 Jan 2024 09:59:58 +0100\n\nb\n\n"
        b"From b@x Tue Jan 16 11:00:00 2024\nFrom: B <b@x>\nSubject: two\nDate: Tue, 16 Jan 2024 11:00:00 -0500\n\nc\n\n"
        b"From c@x Wed Jan 17 12:00:00 2024\nFrom: C <c@x>\nSubject: three\n\nno date\n")


def test_mbox_vs_stdlib_mailbox(tmp_path):
    f = tmp_path / "box.mbox"
    f.write_bytes(MBOX)
    ref = []
    for msg in mailbox.mbox(str(f)):
        d = msg.get("Date")
        ref.append((msg.get("Subject"), int(email.utils.parsedate_to_datetime(d).timestamp()) * NS if d else None))
    ev = list(mbox.MboxParser().parse(str(f), Provenance()))
    recs = {}
    for e in ev:
        recs.setdefault(e.offset, [e.attrs["subject"], None])
        if e.timestamp_desc == "Sent Time":
            recs[e.offset][1] = e.timestamp
    ours = [tuple(v) for v in recs.values()]
    fields = {"subject_and_sent_time": _agree(ours, ref)}
    _write("mbox", {"parser": "py_mbox", "reference": "python stdlib mailbox.mbox + email.utils",
                    "samples": ["synthetic 3-message mbox (tests/parity/test_py_handverified.py)"],
                    "records_ours": len(ours), "records_reference": len(ref), "fields": fields,
                    "notes": "No mbox sample in the plaso corpus; plaso has no mbox parser."})
    assert fields["subject_and_sent_time"]["agree"] == 3


def test_wmi_vs_constructed_fixture(tmp_path):
    from tests.unit.test_parsers_windows import _wmi_fixture

    f = tmp_path / "OBJECTS.DATA"
    f.write_bytes(_wmi_fixture())
    ev = list(wmi.WmiPersistenceParser().parse(str(f), Provenance()))
    ours = sorted((e.data_type, e.attrs.get("name") or e.attrs.get("filter_name")) for e in ev)
    ref = sorted([("wmi:persistence:filter", "BadStartup"), ("wmi:persistence:consumer", "BadConsumer"),
                  ("wmi:persistence:consumer", "ScriptKiddie"), ("wmi:persistence:binding", "BadStartup")])
    fields = {"artifact_and_name": _agree(ours, ref)}
    _write("wmi_persistence", {"parser": "py_wmi_persistence", "reference": "hand-constructed OBJECTS.DATA byte fixture",
                               "samples": ["synthetic (tests/unit/test_parsers_windows.py::_wmi_fixture)"],
                               "records_ours": len(ours), "records_reference": len(ref), "fields": fields,
                               "notes": "No WMI repository in the corpus; carving scanner verified on constructed bytes "
                                        "(UTF-16 and ASCII strings, a class definition decoy and garbage between records)."})
    assert fields["artifact_and_name"]["agree"] == 4
