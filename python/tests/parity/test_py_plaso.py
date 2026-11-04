"""Parity: Veritas Python parsers vs plaso (run in-process on the same corpus samples).

For every case the plaso parser/plugin is run through ``veritas.parsers.parity_ref.run_plaso``
and compared with our parser on:

* ``records``     - number of plaso event-data containers vs our distinct (data_type, offset) records,
* ``timestamps``  - multiset agreement of every date-time value (microseconds; ours rounded
                    half-up from ns), restricted to the data types and timestamp kinds plaso emits,
* named attributes - multiset agreement of per-record attribute values.

Results go to ``parity/results/py_<parser>.json`` (format: parity/README.md). Known, explained
differences are written to ``notes`` and the asserted floors below encode them.
"""
from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from veritas.parsers import registry
from veritas.parsers.base import Provenance
from veritas.parsers.parity_ref import plaso_available, plaso_version, run_plaso
from veritas.timeline.schema import NS

pytestmark = pytest.mark.parity
if not plaso_available():  # pragma: no cover - depends on the optional plaso install
    pytest.skip("plaso not installed", allow_module_level=True)

REPO = Path(__file__).resolve().parents[3]
RESULTS = REPO / "parity" / "results"
PLASO = REPO / "testdata" / "corpus" / "plaso"


def C(ours, sample, parser, plugin=None, **kw):  # noqa: N802 - compact case constructor
    return dict(ours=ours, sample=sample, parser=parser, plugin=plugin, **kw)


# Each case: ours=parser name, sample, plaso parser/plugin, optional:
#   ref_dtypes   data types (plaso) to compare, default all produced by plaso
#   ours_dtypes  our data types to compare, default = ref_dtypes
#   descs        our timestamp_desc values to include (plaso emits fewer kinds for some formats)
#   ref_filter   callable(record) -> bool restricting plaso records
#   ours_filter  callable(event) -> bool restricting our events
#   mode         "abs" (default), "seconds", "dateless" (compare MM-DD hh:mm:ss only), "none"
#   attrs        [(our attr, plaso attr)] per-record multiset comparisons
#   min_ts / min_rec  agreement floors (default 1.0)
#   gzip         plaso reads through a dfVFS gzip layer
CASES: dict[str, list[dict[str, Any]]] = {
    "chromium_history": [
        C("chromium_history", "chrome/History", "sqlite", "chrome_8_history", attrs=[("url", "url"), ("title", "title")]),
        C("chromium_history", "chrome/History-57.0.2987.133", "sqlite", "chrome_27_history", attrs=[("url", "url")]),
        C("chromium_history", "chrome/History-58.0.3029.96", "sqlite", "chrome_27_history", attrs=[("url", "url")]),
        C("chromium_history", "chrome/History-59.0.3071.86", "sqlite", "chrome_27_history", attrs=[("url", "url")]),
    ],
    "chromium_cookies": [C("chromium_cookies", "chrome/Cookies-68.0.3440.106", "sqlite", "chrome_66_cookies",
                           ref_dtypes={"chrome:cookie:entry"}, attrs=[("cookie_name", "cookie_name")])],
    "chromium_webdata": [C("chromium_webdata", "chrome/Web Data", "sqlite", "chrome_autofill",
                           attrs=[("field_name", "field_name"), ("value", "value"), ("usage_count", "usage_count")])],
    "firefox_places": [
        C("firefox_places", "firefox/places.sqlite", "sqlite", "firefox_history", attrs=[("url", "url")],
          ours_dtypes={"firefox:places:page_visited", "firefox:places:bookmark", "firefox:places:bookmark_folder"},
          ref_dtypes={"firefox:places:page_visited", "firefox:places:bookmark", "firefox:places:bookmark_folder"},
          min_rec=0.97, min_ts=0.97),
        C("firefox_places", "firefox/places118.sqlite", "sqlite", "firefox_history", attrs=[("url", "url")],
          ref_dtypes={"firefox:places:page_visited", "firefox:places:bookmark", "firefox:places:bookmark_folder"}),
        C("firefox_places", "firefox/places118.sqlite", "sqlite", "firefox_118_downloads", attrs=[("url", "url")]),
    ],
    "firefox_downloads": [C("firefox_downloads", "firefox/downloads.sqlite", "sqlite", "firefox_downloads",
                            attrs=[("url", "url"), ("full_path", "full_path")])],
    "firefox_cookies": [C("firefox_cookies", "firefox/firefox_10_cookies.sqlite", "sqlite", "firefox_10_cookies",
                          attrs=[("cookie_name", "cookie_name")])],
    "msiecf": [
        C("msiecf", "msiecf/nfury_index.dat", "msiecf", attrs=[("url", "url")], min_rec=0.98, min_ts=0.95),
        C("msiecf", "msiecf/MSHist012013031020130311-index.dat", "msiecf", attrs=[("url", "url")]),
    ],
    "msie_webcache": [C("msie_webcache", "msiecf/WebCacheV01.dat", "esedb", "msie_webcache",
                        ours_filter=lambda e: e.attrs.get("container_name") not in ("iecompat", "iecompatua", "wpnidm"),
                        ref_dtypes={"msie:webcache:containers", "msie:webcache:container", "msie:webcache:partitions"},
                        attrs=[("url", "url")], min_ts=0.95, min_rec=0.95)],
    "srum": [C("srum", "SRUDB.dat", "esedb", "srum")],
    "recycle_bin": [C("recycle_bin", "recycler/$I103S5F.jpg", "recycle_bin", attrs=[("original_filename", "original_filename")]),
                    C("recycle_bin", "recycler/$II3DF3L.zip", "recycle_bin", attrs=[("original_filename", "original_filename")])],
    "recycle_bin_info2": [C("recycle_bin_info2", "recycler/INFO2", "recycle_bin_info2",
                            attrs=[("original_filename", "original_filename"), ("record_index", "record_index")])],
    "windefender_history": [C("windefender_history", f"windefender_history/{n}", "windefender_history",
                              attrs=[("threat_name", "threat_name"), ("filename", "filename"), ("process", "process")])
                            for n in ("6AFE33A0-19BA-4FFF-892F-B700539D7D63", "7C66C39C-49DD-42D7-9822-4039C98CC246",
                                      "FC380697-A68D-4C94-B67F-9B6449039463")],
    "olecf_summary": [C("olecf_summary", "Document.doc", "olecf", "olecf_summary", ref_dtypes={"olecf:summary_info"},
                        ref_time_attrs={"creation_time", "last_save_time", "last_printed_time"},
                        attrs=[("title", "title"), ("author", "author")])],
    "ooxml": [C("ooxml", "Document.docx", "czip", "oxml", ref_dtypes={"openxml:metadata"},
                ours_dtypes={"office:ooxml:metadata"}, attrs=[("creator", "author"), ("revision", "revision_number")])],
    "windows_timeline": [C("windows_timeline", "windows/ActivitiesCache.db", "sqlite", "windows_timeline",
                           descs={"Start Time"}, ours_filter=lambda e: e.attrs.get("table") == "Activity")],
    "powershell_transcript": [C("powershell_transcript", "powershell_transcript.txt", "text", "powershell_transcript")],
    "setupapi": [C("setupapi", "setupapi.dev.log", "text", "setupapi")],
    "syslog": [
        C("syslog", "syslog/syslog_sudo.log", "text", "syslog", min_ts=0.96, min_rec=0.96),
        C("syslog", "syslog/syslog_rsyslog", "text", "syslog"),
        C("syslog", "syslog/syslog_rsyslog_SyslogProtocol23Format", "text", "syslog"),
    ],
    "bash_history": [C("bash_history", "bash_history", "text", "bash_history", attrs=[("command", "command")])],
    "zsh_extended_history": [C("zsh_extended_history", "zsh_extended_history.txt", "text", "zsh_extended_history",
                               attrs=[("command", "command")])],
    "fish_history": [C("fish_history", "fish_history", "fish_history", attrs=[("command", "command")])],
    "dpkg": [C("dpkg", "dpkg.log", "text", "dpkg")],
    "apt_history": [C("apt_history", "apt_history.log", "text", "apt_history", attrs=[("command_line", "command_line")])],
    "apache_access": [C("apache_access", "apache_access.log", "text", "apache_access", min_rec=0.93, min_ts=0.93, min_attr=0.93,
                        attrs=[("ip_address", "ip_address")])],
    "utmp": [C("utmp", "utmp/utmp", "utmp", attrs=[("username", "username")]),
             C("utmp", "utmp/wtmp.1", "utmp", min_rec=0.5)],
    "utmpx_macos": [C("utmpx_macos", "utmpx_mac", "utmpx", attrs=[("username", "username")])],
    "asl_log": [C("asl_log", "2019.09.26.asl", "asl_log", attrs=[("sender", "sender"), ("facility", "facility")])],
    "bsm_log": [C("bsm_log", "apple.bsm", "bsm_log", mode="seconds"), C("bsm_log", "openbsm.bsm", "bsm_log", mode="seconds")],
    "fseventsd": [C("fseventsd", "fsevents/fsevents-00000000001a0b79", "fseventsd", gzip=True, mode="none",
                    attrs=[("path", "path"), ("event_identifier", "event_identifier"), ("flags", "flags")]),
                  C("fseventsd", "fsevents/fsevents-0000000002d89b58", "fseventsd", gzip=True, mode="none",
                    attrs=[("path", "path"), ("event_identifier", "event_identifier"), ("flags", "flags")])],
    "knowledgec": [C("knowledgec", "macos/knowledgec-10.14.db", "sqlite", "mac_knowledgec"),
                   C("knowledgec", "macos/knowledgec-10.13.db", "sqlite", "mac_knowledgec")],
    "ls_quarantine": [C("ls_quarantine", "sqlite/quarantine.db", "sqlite", "ls_quarantine", attrs=[("url", "url"), ("agent", "agent")])],
    "macos_tcc": [C("macos_tcc", "macos/TCC-test.db", "sqlite", "macostcc", attrs=[("client", "client")])],
    "macos_appusage": [C("macos_appusage", "macos/application_usage.sqlite", "sqlite", "appusage",
                         attrs=[("application", "application")])],
    "macos_notification_center": [C("macos_notification_center", "mac_notificationcenter.db", "sqlite",
                                    "mac_notificationcenter", attrs=[("title", "title")])],
    "imessage": [C("imessage", "sqlite/imessage_chat.db", "sqlite", "imessage", descs={"Creation Time"},
                   attrs=[("text", "text")])],
    "santa": [C("santa", "santa.log", "text", "santa", min_ts=0.99)],
    "macos_wifi": [C("macos_wifi", "wifi.log", "text", "mac_wifi", mode="dateless")],
    "mac_appfirewall_log": [C("mac_appfirewall_log", "appfirewall.log", "text", "mac_appfirewall_log", mode="dateless",
                              attrs=[("process_name", "process_name")])],
    "macos_launchd_log": [C("macos_launchd_log", "macos_launchd.log", "text", "macos_launchd_log")],
    "launchd_plist": [C("launchd_plist", "plist/launchd.minimal.plist", "plist", "launchd_plist", mode="none",
                        attrs=[("label", "name"), ("program", "program")])],
    "macos_background_items": [C("macos_background_items", "backgrounditems.btm", "plist", "macos_background_items_plist",
                                 mode="none", attrs=[("target_path", "target_path")])],
}

NOTES = {
    "chromium_webdata": "plaso's chrome_autofill plugin reads only the autofill table; keyword (search engine) events are Veritas-only.",
    "firefox_places": "places.sqlite: Veritas also emits two bookmark rows whose moz_places entry is missing (plaso drops them) and "
                      "per-annotation events for all moz_items_annos rows (plaso: 3); compared types exclude annotations.",
    "msiecf": "Veritas additionally emits records recovered from unallocated blocks (attrs.recovered=true); plaso's "
              "'synchronization_time' is Veritas 'Last Checked Time' (URL record offset 0x50).",
    "msie_webcache": "plaso skips the iecompat, iecompatua and wpnidm containers; they are excluded from the comparison. "
                     "Pre-1970 FILETIME values are treated as invalid by Veritas.",
    "srum": "Compared: application resource usage, network usage, network connectivity. Veritas also decodes the app "
            "timeline and energy tables (no plaso equivalent).",
    "olecf_summary": "plaso additionally emits olecf:item events for OLE directory entries (not a metadata parser concern).",
    "windows_timeline": "plaso emits only StartTime; Veritas also emits End, LastModified and Expiration times.",
    "syslog": "Year-less BSD syslog samples are not comparable in-process (plaso resolves years through its date-less "
              "log helper at timeline time); they are verified against the raw text in test_py_handverified. "
              "syslog_sudo: Veritas keeps one multi-line sudo record that plaso's grammar rejects.",
    "apache_access": "Veritas accepts one line plaso rejects; plaso and Veritas both accept requests with embedded quotes.",
    "bash_history": "Multi-line commands: Veritas keeps the newlines, plaso joins with spaces (compared whitespace-normalised).",
    "zsh_extended_history": "Multi-line commands: Veritas keeps the newlines, plaso joins with spaces (compared whitespace-normalised).",
    "launchd_plist": "plaso attribute 'name' is Veritas 'label'.",
    "ooxml": "plaso data type openxml:metadata / attribute 'author' correspond to Veritas office:ooxml:metadata / 'creator'.",
    "utmp": "Terminal '~' is rendered 'system boot' by plaso (not compared). wtmp.1: plaso emits 4 records, two of them non-text garbage; Veritas skips those with a warning.",
    "bsm_log": "Compared at one-second resolution: plaso interprets the header32 'milliseconds' field as microseconds "
               "(e.g. 1383590180.000381); Veritas follows the OpenBSM spec (1383590180.381).",
    "fseventsd": "Records compared on path/event id/flags; event times are the fseventsd file mtime in both tools.",
    "santa": "plaso also emits 'appearance' times equal to the Cocoa epoch (2001-01-01, i.e. unset); Veritas omits them.",
    "macos_wifi": "Year-less: compared on month..second.",
    "mac_appfirewall_log": "Year-less: compared on month..second.",
    "imessage": "plaso emits only the message date; Veritas also emits read/delivered times.",
}


def _us(ns: int) -> int:
    return (ns + 500) // 1000


def _agreement(a: list, b: list) -> tuple[int, int]:
    ca, cb = Counter(a), Counter(b)
    return sum(min(ca[k], cb[k]) for k in ca), max(sum(ca.values()), sum(cb.values()))


def _run_case(case: dict[str, Any]) -> dict[str, Any]:
    path = PLASO / case["sample"]
    logging.disable(logging.CRITICAL)
    try:
        ref = run_plaso(str(path), case["parser"], case["plugin"], gzip=case.get("gzip", False))
    finally:
        logging.disable(logging.NOTSET)
    ref_dtypes = case.get("ref_dtypes") or {r["data_type"] for r in ref}
    ref = [r for r in ref if r["data_type"] in ref_dtypes and case.get("ref_filter", lambda r: True)(r)]
    ours_dtypes = case.get("ours_dtypes") or ref_dtypes
    parser = registry.get(case["ours"])()
    events = [e for e in parser.parse(str(path), Provenance(evidence_path=case["sample"]))
              if e.data_type in ours_dtypes and case.get("ours_filter", lambda e: True)(e)]
    descs = case.get("descs")
    mode = case.get("mode", "abs")
    timed = [e for e in events if e.timestamp is not None and (descs is None or e.timestamp_desc in descs)]
    tattrs = case.get("ref_time_attrs")
    ref_times = [(k, v) for r in ref for k, v in r["times"].items() if v and (tattrs is None or k in tattrs)]
    if mode == "abs":
        ours_t, ref_t = [_us(e.timestamp) for e in timed], [v for _, v in ref_times]
    elif mode == "seconds":
        ours_t, ref_t = [e.timestamp // NS for e in timed], [v // 1_000_000 for _, v in ref_times]
    elif mode == "dateless":
        from veritas.timeline.schema import format_ns

        ours_t = [format_ns(e.timestamp)[5:19].replace("T", " ") for e in timed]
        ref_t = [s[5:19] for r in ref for k, s in r.get("time_strings", {}).items()]
    else:
        ours_t, ref_t = [], []
    records = {}
    for e in events:
        records.setdefault((e.data_type, e.offset), e)
    out = {"records_ours": len(records), "records_reference": len(ref), "fields": {}}
    if mode != "none":
        agree, total = _agreement(ours_t, ref_t)
        out["fields"]["timestamps"] = {"agree": agree, "total": total}
    for ours_attr, ref_attr in case.get("attrs", []):
        # Whitespace is normalised: plaso joins multi-line shell commands with spaces.
        a = [" ".join(str(e.attrs.get(ours_attr)).split()) for e in records.values() if e.attrs.get(ours_attr) not in (None, "")]
        b = [" ".join(str(r["attrs"].get(ref_attr)).split()) for r in ref if r["attrs"].get(ref_attr) not in (None, "")]
        agree, total = _agreement(a, b)
        out["fields"][ours_attr] = {"agree": agree, "total": total}
    return out


@pytest.mark.parametrize("name", sorted(CASES))
def test_parity_vs_plaso(name):
    if not PLASO.is_dir():
        pytest.skip("corpus not present")
    summary = {"parser": f"py_{name}", "reference": plaso_version(), "samples": [], "records_ours": 0,
               "records_reference": 0, "fields": {}, "notes": NOTES.get(name, "")}
    failures = []
    for case in CASES[name]:
        res = _run_case(case)
        summary["samples"].append(f"plaso/{case['sample']}")
        summary["records_ours"] += res["records_ours"]
        summary["records_reference"] += res["records_reference"]
        for field, v in res["fields"].items():
            f = summary["fields"].setdefault(field, {"agree": 0, "total": 0})
            f["agree"] += v["agree"]
            f["total"] += v["total"]
        rec_ratio = min(res["records_ours"], res["records_reference"]) / max(res["records_ours"], res["records_reference"], 1)
        if rec_ratio < case.get("min_rec", 1.0):
            failures.append(f"{case['sample']}: records {res['records_ours']} vs {res['records_reference']}")
        for field, v in res["fields"].items():
            ratio = v["agree"] / v["total"] if v["total"] else 1.0
            floor = case.get("min_ts", 1.0) if field == "timestamps" else case.get("min_attr", 0.95)
            if ratio < floor:
                failures.append(f"{case['sample']}: {field} {v['agree']}/{v['total']}")
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"py_{name}.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert not failures, failures
