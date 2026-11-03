import json

import pytest

from veritas.timeline.schema import Desc, Event, format_ns, iso_to_ns, read_jsonl, write_jsonl
from veritas.timeline.skew import HostClock, apply_skew, local_to_utc_ns, localize, normalize
from veritas.timeline.store import Query, SqliteTimelineStore, event_fingerprint, open_store
from zoneinfo import ZoneInfo


def mk(i: int, **kw) -> Event:
    base = dict(
        data_type="windows:evtx:record", timestamp_desc=Desc.EVENT, message=f"event number {i} from host",
        timestamp=1_700_000_000_000_000_000 + i * 60_000_000_000, evidence_sha256="e" * 64, evidence_path="C:/Windows/System32/winevt/Logs/Security.evtx",
        offset=i, parser="evtx", parser_version="0.1.0", host="WS01", user="alice", attrs={"event_identifier": 4624 + (i % 3), "logon_type": "3"},
    )
    base.update(kw)
    return Event(**base)


@pytest.fixture
def store(tmp_path):
    return SqliteTimelineStore(tmp_path / "timeline.db")


def test_ingest_search_facets_histogram(store):
    n = store.ingest("CASE-1", (mk(i) for i in range(100)))
    assert n == 100
    assert store.count("CASE-1") == 100
    assert store.count("CASE-2") == 0
    res = store.search("CASE-1", Query(text="number 42"))
    assert res.total == 1 and res.events[0].event.offset == 42
    res = store.search("CASE-1", Query(attr_equals={"event_identifier": "4625"}))
    assert res.total == 33
    res = store.search("CASE-1", Query(start_ns=mk(10).timestamp, end_ns=mk(20).timestamp, limit=5))
    assert res.total == 10 and len(res.events) == 5
    facets = store.facets("CASE-1", Query(), "data_type")
    assert facets == [("windows:evtx:record", 100)]
    hist = store.histogram("CASE-1", Query(), 10 * 60_000_000_000)
    assert sum(b.count for b in hist) == 100 and len(hist) in (10, 11)
    with pytest.raises(ValueError):
        store.facets("CASE-1", Query(), "attrs")


def test_idempotent_ingest_and_case_isolation(store):
    store.ingest("CASE-1", [mk(1), mk(2)])
    assert store.ingest("CASE-1", [mk(1), mk(2), mk(3)]) == 1
    store.ingest("CASE-2", [mk(1)])
    assert store.search("CASE-1", Query(text="number")).total == 3
    assert store.search("CASE-2", Query(text="number")).total == 1
    got = store.get("CASE-1", store.search("CASE-1", Query(limit=1)).events[0].id)
    assert got is not None and store.get("CASE-2", got.id) is None
    assert store.delete_case("CASE-1") == 3
    assert store.count("CASE-1") == 0 and store.count("CASE-2") == 1


def test_untimed_events_and_ordering(store):
    store.ingest("C", [mk(5), mk(1, timestamp=None), mk(3)])
    res = store.search("C", Query())
    assert [e.event.offset for e in res.events] == [3, 5]
    res = store.search("C", Query(include_untimed=True, descending=True))
    assert [e.event.offset for e in res.events] == [5, 3, 1]
    assert [e.event.offset for e in store.iter_events("C")] == [1, 3, 5]


def test_fts_injection_is_quoted(store):
    store.ingest("C", [mk(1, message='weird "quoted" OR text NEAR/2')])
    assert store.search("C", Query(text='"quoted" OR')).total == 1
    assert store.search("C", Query(text="NEAR/2 tex*")).total == 1
    assert store.search("C", Query(text="nothere")).total == 0


def test_open_store_sqlite(tmp_path):
    s = open_store(f"sqlite:///{tmp_path / 'x.db'}")
    assert s.count("x") == 0
    with pytest.raises(ValueError):
        open_store("postgres://x")


def test_fingerprint_stable():
    assert event_fingerprint("A", mk(1)) == event_fingerprint("A", mk(1))
    assert event_fingerprint("A", mk(1)) != event_fingerprint("B", mk(1))


def test_schema_roundtrip_and_time_helpers(tmp_path):
    p = tmp_path / "e.jsonl"
    evs = [mk(2), mk(1, host=None), mk(0, timestamp=None)]
    with p.open("w", encoding="utf-8") as fh:
        assert write_jsonl(evs, fh) == 3
    back = list(read_jsonl(p.open(encoding="utf-8")))
    assert [b.offset for b in back] == [0, 1, 2]
    assert back[1].host is None
    assert iso_to_ns("2024-01-02T03:04:05.123456Z") == 1704164645123456000
    assert iso_to_ns("2024-01-02T03:04:05+02:00") == iso_to_ns("2024-01-02T01:04:05Z")
    assert iso_to_ns("garbage") is None
    assert format_ns(1704164645123456000) == "2024-01-02T03:04:05.123456Z"


def test_skew_and_localization():
    clock = HostClock("e" * 64, tz_name="Europe/Berlin", skew_ns=5_000_000_000)
    e = mk(1, attrs={"time_is_local": True})
    naive = e.timestamp
    e = localize(e, clock)
    assert e.timestamp == local_to_utc_ns(naive, ZoneInfo("Europe/Berlin"))
    assert e.timezone == "Europe/Berlin" and "time_is_local" not in e.attrs
    before = e.timestamp
    e = apply_skew(e, clock)
    assert e.timestamp == before - 5_000_000_000 and e.skew_ns == -5_000_000_000
    assert apply_skew(e, clock).timestamp == before - 5_000_000_000  # idempotent
    ext = mk(2, attrs={"time_source": "external"})
    assert apply_skew(ext, clock).skew_ns == 0
    out = list(normalize([mk(3)], {"e" * 64: clock}))
    assert out[0].skew_ns == -5_000_000_000
