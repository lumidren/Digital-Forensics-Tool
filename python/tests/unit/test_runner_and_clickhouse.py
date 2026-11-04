"""In-process tests of the parser runner, and the ClickHouse timeline backend.

The ClickHouse tests run against a real server when CLICKHOUSE_URL is set (CI integration job with
a service container) and otherwise against an in-memory fake of the HTTP interface that executes
the generated SQL's semantics for the subset the store uses.
"""
import json
import os
import re
from pathlib import Path

import httpx
import pytest

from veritas.pipeline import runner
from veritas.timeline.schema import Desc, Event
from veritas.timeline.store import ClickHouseTimelineStore, Query, open_store

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "testdata" / "corpus" / "plaso"


def _out(capfd):
    return [json.loads(l) for l in capfd.readouterr().out.splitlines() if l.strip()]


@pytest.mark.skipif(runner.find_binary("veritas-artifacts-dump") is None or not (CORPUS / "NeroInfoTool.lnk").exists(), reason="needs binaries and corpus")
def test_runner_rust_kind_relabels_paths(capfd):
    assert runner.main(["lnk", str(CORPUS / "NeroInfoTool.lnk"), "a" * 64, "Users/x/Recent/Nero.lnk"]) == 0
    evs = _out(capfd)
    assert evs and all(e["evidence_path"] == "Users/x/Recent/Nero.lnk" and e["evidence_sha256"] == "a" * 64 for e in evs)


@pytest.mark.skipif(runner.find_binary("fs-tool") is None or not (CORPUS / "UsnJrnl.raw").exists(), reason="needs binaries and corpus")
def test_runner_fs_kind_keeps_inner_paths(capfd):
    assert runner.main(["usn", str(CORPUS / "UsnJrnl.raw"), "b" * 64, "$Extend/$UsnJrnl:$J"]) == 0
    evs = _out(capfd)
    assert len(evs) == 19 and all(e["data_type"] == "fs:ntfs:usn_change" for e in evs)


def test_runner_python_kind_and_errors(capfd, tmp_path):
    hist = CORPUS / "bash_history"
    if hist.exists():
        assert runner.main(["auto", str(hist), "c" * 64, "home/u/.bash_history"]) == 0
        evs = _out(capfd)
        assert evs and evs[0]["evidence_path"] == "home/u/.bash_history"
    assert runner.main(["nope", str(tmp_path), "0", "x"]) == 1
    assert "unknown parser" in json.loads(capfd.readouterr().err.splitlines()[-1])["msg"]
    junk = tmp_path / "junk.bin"
    junk.write_bytes(os.urandom(64))
    assert runner.main(["auto", str(junk), "0", "junk.bin"]) == 1
    capfd.readouterr()


def test_runner_missing_binary(monkeypatch, capfd, tmp_path):
    monkeypatch.setattr(runner, "find_binary", lambda name: None)
    assert runner.main(["evtx", str(tmp_path), "0", "x"]) == 1
    assert "not found" in capfd.readouterr().err


# ----------------------------------------------------------------------------- ClickHouse
class FakeClickHouse:
    """Tiny interpreter for the SQL ClickHouseTimelineStore emits (enough to check semantics)."""

    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.sql: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("query", "").strip()
        self.sql.append(q)
        body = request.content.decode("utf-8")
        if q.startswith(("CREATE", "ALTER")):
            if "DELETE WHERE case_id" in q:
                cid = re.search(r"case_id = '([^']*)'", q).group(1)
                self.rows = {k: v for k, v in self.rows.items() if v["case_id"] != cid}
            return httpx.Response(200, text="")
        if q.startswith("INSERT"):
            for line in body.splitlines():
                d = json.loads(line)
                self.rows[d["fingerprint"]] = d
            return httpx.Response(200, text="")
        rows = [r for r in self.rows.values() if self._where(q, r)]
        if q.startswith("SELECT count()"):
            return httpx.Response(200, text=f"{len(rows)}\n")
        if "intDiv(timestamp" in q:
            b = int(re.search(r"intDiv\(timestamp, (\d+)\)", q).group(1))
            counts: dict[int, int] = {}
            for r in rows:
                k = r["timestamp"] // b * b
                counts[k] = counts.get(k, 0) + 1
            return httpx.Response(200, text="\n".join(json.dumps({"b": k, "n": n}) for k, n in sorted(counts.items())))
        m = re.match(r"SELECT (\w+) AS v, count\(\) AS n", q)
        if m:
            col = m.group(1)
            counts = {}
            for r in rows:
                counts[r[col]] = counts.get(r[col], 0) + 1
            return httpx.Response(200, text="\n".join(json.dumps({"v": k, "n": n}) for k, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))))
        rows.sort(key=lambda r: (r["timestamp"] if r["timestamp"] is not None else -(2**63), r["data_type"], r["evidence_path"], r["offset"]), reverse="DESC" in q)
        lim = int(re.search(r"LIMIT (\d+)", q).group(1))
        off = int(re.search(r"OFFSET (\d+)", q).group(1))
        return httpx.Response(200, text="\n".join(json.dumps(r) for r in rows[off:off + lim]))

    @staticmethod
    def _where(q: str, r: dict) -> bool:
        if "WHERE" not in q:
            return True
        cid = re.search(r"case_id = '([^']*)'", q)
        if cid and r["case_id"] != cid.group(1):
            return False
        if "timestamp IS NOT NULL" in q and r["timestamp"] is None:
            return False
        lo = re.search(r"timestamp >= (-?\d+)", q)
        if lo and (r["timestamp"] is None or r["timestamp"] < int(lo.group(1))):
            return False
        hi = re.search(r"timestamp < (-?\d+)", q)
        if hi and (r["timestamp"] is None or r["timestamp"] >= int(hi.group(1))):
            return False
        dts = re.search(r"data_type IN \(([^)]*)\)", q)
        if dts and repr(r["data_type"]).replace('"', "'") not in dts.group(1):
            return False
        for tok in re.findall(r"positionCaseInsensitive\(message, '([^']*)'\)", q):
            if tok.lower() not in r["message"].lower() and tok.lower() not in r["attrs"].lower():
                return False
        return True


def mk(i, case_ts=1_700_000_000_000_000_000, **kw):
    return Event(data_type=kw.pop("data_type", "windows:evtx:record"), timestamp_desc=Desc.EVENT, message=kw.pop("message", f"logon {i}"), timestamp=case_ts + i * 10**9,
                 evidence_sha256="e" * 64, evidence_path="Security.evtx", offset=i, parser="evtx", parser_version="1", attrs={"n": i})


@pytest.fixture
def ch(monkeypatch):
    real = os.environ.get("CLICKHOUSE_URL")
    if real:
        from urllib.parse import urlparse

        u = urlparse(real)
        store = ClickHouseTimelineStore(f"{u.scheme}://{u.hostname}:{u.port}", database="veritas_test", user=u.username, password=u.password)
        yield store, None
        store._sql("DROP DATABASE IF EXISTS veritas_test")
        return
    fake = FakeClickHouse()
    orig = httpx.Client

    def client(**kw):
        kw.pop("auth", None)
        return orig(transport=httpx.MockTransport(fake.handler), **kw)

    monkeypatch.setattr(httpx, "Client", client)
    yield ClickHouseTimelineStore("http://clickhouse:8123", database="veritas"), fake


def _check(store):
    assert store.ingest("C1", [mk(i) for i in range(10)] + [mk(99, message="special token")]) == 11
    store.ingest("C2", [mk(1)])
    assert store.count("C1") == 11 and store.count("C2") == 1
    res = store.search("C1", Query(limit=3))
    assert res.total == 11 and [e.event.offset for e in res.events] == [0, 1, 2]
    assert store.search("C1", Query(text="special", limit=5)).total == 1
    assert store.search("C1", Query(start_ns=mk(2).timestamp, end_ns=mk(5).timestamp)).total == 3
    assert store.search("C1", Query(descending=True, limit=1)).events[0].event.offset == 99
    assert sum(b.count for b in store.histogram("C1", Query(), 60 * 10**9)) == 11
    assert store.facets("C1", Query(), "data_type") == [("windows:evtx:record", 11)]
    with pytest.raises(ValueError):
        store.facets("C1", Query(), "attrs")
    assert len(list(store.iter_events("C1"))) == 11
    assert store.get("C1", 0).event.offset == 0
    assert store.delete_case("C1") == 11


def test_clickhouse_backend_contract(ch):
    store, fake = ch
    _check(store)
    if fake is not None:
        # Every query is scoped by case id inside the store (THREAT:T4.2) and values are escaped.
        selects = [s for s in fake.sql if s.startswith("SELECT")]
        assert selects and all("case_id = '" in s for s in selects)
        store.search("C1'; DROP TABLE x; --", Query(text="o'brien"))
        assert "case_id = 'C1\\'; DROP TABLE x; --'" in fake.sql[-1] and "o\\'brien" in fake.sql[-1]


@pytest.mark.integration
@pytest.mark.skipif(not os.environ.get("CLICKHOUSE_URL"), reason="CLICKHOUSE_URL not set (runs in CI with a ClickHouse service)")
def test_clickhouse_real_server(ch):
    store, fake = ch
    assert fake is None
    _check(store)


def test_open_store_clickhouse_url(monkeypatch):
    fake = FakeClickHouse()
    orig = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: orig(transport=httpx.MockTransport(fake.handler), **{k: v for k, v in kw.items() if k != "auth"}))
    assert isinstance(open_store("clickhouse://localhost:8123/veritas"), ClickHouseTimelineStore)
