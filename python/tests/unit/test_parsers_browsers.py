"""Unit tests: Chromium, Firefox and legacy IE/Edge parsers on the plaso corpus samples."""
from __future__ import annotations

from collections import Counter

import pytest

from veritas.parsers.base import ParserError, Provenance
from veritas.parsers.browsers import chromium, firefox, ie_edge_legacy


def run(cls, path):
    p = cls()
    events = list(p.parse(str(path), Provenance(evidence_path=str(path), evidence_sha256="0" * 64)))
    return events, p


def kinds(events):
    return Counter((e.data_type, e.timestamp_desc) for e in events)


def test_chrome_history_legacy_schema(corpus):
    ev, p = run(chromium.ChromiumHistoryParser, corpus / "plaso/chrome/History")
    assert p.warning_count == 0
    k = kinds(ev)
    assert k[("chrome:history:page_visited", "Last Visited Time")] == 69
    assert k[("chrome:history:file_downloaded", "Start Time")] == 2
    first = ev[0]
    assert first.timestamp == 1302177791000000000
    assert first.attrs["url"] == "http://start.ubuntu.com/10.04/Google/"
    assert first.attrs["title"] == "Ubuntu Start Page"
    assert first.attrs["page_transition"].startswith("LINK")
    dl = [e for e in ev if e.data_type == "chrome:history:file_downloaded"]
    # Chrome <= 26 stored download start_time as Unix seconds.
    assert dl[-1].timestamp == 1306139765000000000
    assert dl[-1].attrs["full_path"] == "/home/john/Downloads/Cats Demo.exe"
    assert dl[-1].attrs["received_bytes"] == 1308799
    assert first.evidence_sha256 == "0" * 64 and first.parser == "chromium_history"


@pytest.mark.parametrize("name,start,end", [
    ("History-57.0.2987.133", 1516543793900399000, 1516543794858738000),
    ("History-58.0.3029.96", 1516543767200398000, 1516543768116062000),
    ("History-59.0.3071.86", 1516543731811123000, 1516543732662377000),
])
def test_chrome_history_modern_schemas(corpus, name, start, end):
    ev, _ = run(chromium.ChromiumHistoryParser, corpus / "plaso/chrome" / name)
    k = kinds(ev)
    assert k[("chrome:history:page_visited", "Last Visited Time")] == 1
    dl = {e.timestamp_desc: e for e in ev if e.data_type == "chrome:history:file_downloaded"}
    assert dl["Start Time"].timestamp == start
    assert dl["End Time"].timestamp == end
    assert dl["Start Time"].attrs["url"].endswith("plaso-20171231.1.win32.msi")
    assert dl["Start Time"].attrs["danger_type_name"] is not None
    assert dl["Start Time"].attrs["full_path"] == "/home/ubuntu/Downloads/plaso-20171231.1.win32.msi"


def test_chrome_cookies(corpus):
    ev, _ = run(chromium.ChromiumCookiesParser, corpus / "plaso/chrome/Cookies-68.0.3440.106")
    k = kinds(ev)
    assert k == Counter({("chrome:cookie:entry", "Creation Time"): 5, ("chrome:cookie:entry", "Last Access Time"): 5,
                         ("chrome:cookie:entry", "Expiration Time"): 5})
    assert ev[0].attrs["cookie_name"] == "__utma"
    assert ev[0].timestamp == 1534259023650324000


def test_chrome_web_data(corpus):
    ev, _ = run(chromium.ChromiumWebDataParser, corpus / "plaso/chrome/Web Data")
    autofill = [e for e in ev if e.data_type == "chrome:autofill:entry"]
    assert len(autofill) == 6
    assert autofill[0].attrs["value"] == "name@example.com"
    assert autofill[0].attrs["usage_count"] == 2
    assert autofill[0].timestamp == 1534259242000000000
    assert sum(1 for e in ev if e.data_type == "chrome:webdata:keyword") == 16


def test_chrome_module_parse_dispatch(corpus):
    ev = list(chromium.parse(str(corpus / "plaso/chrome/History"), Provenance()))
    assert len(ev) == 71
    with pytest.raises(ParserError):
        list(chromium.parse(str(corpus / "plaso/dpkg.log"), Provenance()))


def test_firefox_places_old(corpus):
    ev, _ = run(firefox.FirefoxPlacesParser, corpus / "plaso/firefox/places.sqlite")
    k = kinds(ev)
    assert len(ev) == 212
    assert k[("firefox:places:page_visited", "Last Visited Time")] == 1
    assert k[("firefox:places:bookmark", "Added Time")] == 93
    visit = next(e for e in ev if e.data_type == "firefox:places:page_visited")
    assert visit.timestamp == 1309518981371935000
    assert visit.attrs["url"] == "http://news.google.com/" and visit.attrs["typed"] is True


def test_firefox_places_118_with_download_annotations(corpus):
    ev, _ = run(firefox.FirefoxPlacesParser, corpus / "plaso/firefox/places118.sqlite")
    k = kinds(ev)
    assert len(ev) == 127
    assert k[("firefox:places:page_visited", "Last Visited Time")] == 89
    assert k[("firefox:downloads:download", "Start Time")] == 7
    assert k[("firefox:downloads:download", "End Time")] == 7
    dl = [e for e in ev if e.data_type == "firefox:downloads:download"]
    assert any(e.attrs["full_path"].endswith("python-3.12.0-amd64.exe") for e in dl)


def test_firefox_downloads_legacy(corpus):
    ev, _ = run(firefox.FirefoxDownloadsParser, corpus / "plaso/firefox/downloads.sqlite")
    assert [e.timestamp for e in ev] == [1374173999312000000, 1374174078578000000]
    assert ev[0].attrs["total_bytes"] == 15974599


def test_firefox_cookies(corpus):
    ev, _ = run(firefox.FirefoxCookiesParser, corpus / "plaso/firefox/firefox_10_cookies.sqlite")
    assert len(ev) == 39
    assert ev[0].attrs["cookie_name"] == "GPS" and ev[0].attrs["host"] == ".youtube.com"


def test_firefox_module_parse(corpus):
    assert len(list(firefox.parse(str(corpus / "plaso/firefox/downloads.sqlite"), Provenance()))) == 2


def test_msiecf_index_dat(corpus):
    ev, p = run(ie_edge_legacy.MsiecfParser, corpus / "plaso/msiecf/nfury_index.dat")
    assert p.warning_count == 0
    k = kinds(ev)
    assert len(ev) == 2914
    assert k[("msiecf:url", "Last Access Time")] == 991
    assert k[("msiecf:redirected", "Not a time")] == 34
    first = ev[0]
    assert first.attrs["url"] == "http://col.stc.s-msn.com/br/gbl/lg/csl/favicon.ico"
    assert first.timestamp == 1289375670092000000
    assert first.attrs["cached_filename"] == "favicon[1].ico"


def test_msiecf_history_index(corpus):
    ev, _ = run(ie_edge_legacy.MsiecfParser, corpus / "plaso/msiecf/MSHist012013031020130311-index.dat")
    assert len(ev) == 83
    assert kinds(ev)[("msiecf:url", "Last Visited Time")] == 23


def test_webcache(corpus):
    ev, p = run(ie_edge_legacy.WebCacheParser, corpus / "plaso/msiecf/WebCacheV01.dat")
    assert p.warning_count == 0
    k = kinds(ev)
    assert len(ev) == 3864  # 12 pre-1970 wpnidm values dropped, 7 Partitions rows (3 timed + 4 Not a time) added
    assert k[("msie:webcache:containers", "Last Access Time")] == 21
    assert k[("msie:webcache:container", "Last Access Time")] == 1549
    hist = [e for e in ev if e.data_type == "msie:webcache:container" and e.attrs["container_name"].startswith("MSHist")]
    assert any("forensicswiki.org" in e.attrs["url"] for e in hist)
