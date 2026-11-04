import json
import sys

import pytest

from veritas.pipeline import runner
from veritas.pipeline.dag import DONE, FAILED, SKIPPED, Dag, JobStore, Step, execute, step_key
from veritas.pipeline.worker import Limits, describe_limits, run_parser


def test_dag_order_cache_and_resume(tmp_path):
    calls: list[str] = []

    def mk(name, fail_times=0):
        state = {"n": 0}

        def fn(ctx):
            calls.append(name)
            state["n"] += 1
            if state["n"] <= fail_times:
                raise RuntimeError("transient")
            ctx.progress(0.5, "half")
            return {"step": name, "inputs": sorted(ctx.inputs)}

        return fn

    dag = Dag([Step("c", mk("c"), ["a", "b"]), Step("a", mk("a")), Step("b", mk("b", fail_times=1), ["a"])])
    assert dag.order == ["a", "b", "c"]
    store = JobStore(tmp_path / "jobs.db")
    store.create_job("J1", "C1", "s" * 64, "disk")
    events = []
    assert execute(dag, store, "J1", "C1", "s" * 64, events.append) == DONE
    assert calls == ["a", "b", "b", "c"]
    assert store.step_output("J1", "c") == {"step": "c", "inputs": ["a", "b"]}
    assert any(e.get("progress") == 0.5 for e in events)
    # Second job over the same evidence reuses every cached step.
    store.create_job("J2", "C1", "s" * 64, "disk")
    calls.clear()
    assert execute(dag, store, "J2", "C1", "s" * 64) == DONE
    assert calls == []
    job = store.job("J2")
    assert job["state"] == DONE and len(job["steps"]) == 3 and store.queue_depth() == 0


def test_dag_failure_skips_dependents_and_resume(tmp_path):
    flag = {"fail": True}

    def flaky(ctx):
        if flag["fail"]:
            raise ValueError("boom")
        return {"ok": True}

    dag = Dag([Step("a", flaky, retries=0), Step("b", lambda ctx: {"b": 1}, ["a"]), Step("x", lambda ctx: {"x": 1})])
    store = JobStore(tmp_path / "jobs.db")
    store.create_job("J", "C", "e" * 64, "triage")
    assert execute(dag, store, "J", "C", "e" * 64) == FAILED
    states = {s["name"]: s["state"] for s in store.job("J")["steps"]}
    assert states == {"a": FAILED, "b": SKIPPED, "x": DONE}
    assert store.next_job() is None
    # Resume after the fault is fixed: only failed/skipped steps rerun.
    flag["fail"] = False
    store.set_job("J", "pending")
    store.reset_failed_steps("J")
    assert execute(dag, store, "J", "C", "e" * 64) == DONE


def test_concurrent_claims_are_exclusive(tmp_path):
    import threading

    db = tmp_path / "jobs.db"
    JobStore(db).create_job("J1", "C", "e" * 64, "disk")
    JobStore(db).create_job("J2", "C", "f" * 64, "triage")
    winners: list[tuple] = []
    lock = threading.Lock()

    def worker(i):
        s = JobStore(db, worker_id=f"w{i}")
        while (j := s.next_job()) is not None:
            with lock:
                winners.append((j[0], s.worker_id))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert sorted(w[0] for w in winners) == ["J1", "J2"]  # each job claimed exactly once
    s = JobStore(db, worker_id="late")
    assert s.next_job() is None
    # An expired lease makes a running job claimable again (crashed worker).
    s._x("UPDATE jobs SET lease_until = :t WHERE job_id = 'J1'", t="2000-01-01T00:00:00.000000Z")
    assert s.next_job()[0] == "J1" and s.job("J1")["claimed_by"] == "late"
    s.set_job("J1", "done")
    assert s.job("J1")["claimed_by"] is None


def test_priority_order(tmp_path):
    s = JobStore(tmp_path / "j.db")
    s.create_job("disk", "C", "a" * 64, "disk")
    s.create_job("tri", "C", "b" * 64, "triage")
    assert s.next_job()[0] == "tri" and s.next_job()[0] == "disk"


def test_dag_rejects_cycles_and_unknown():
    with pytest.raises(ValueError):
        Dag([Step("a", lambda c: {}, ["b"]), Step("b", lambda c: {}, ["a"])])
    with pytest.raises(ValueError):
        Dag([Step("a", lambda c: {}, ["zz"])])
    assert step_key("a", "b", "1", {"x": 1}) == step_key("a", "b", "1", {"x": 1})


@pytest.fixture
def fake_parser(monkeypatch, tmp_path):
    mod = tmp_path / "fakeparsers.py"
    mod.write_text(
        "import socket, time\n"
        "from veritas.timeline.schema import Event\n"
        "def good(path, prov):\n"
        "    yield Event(data_type='t', timestamp_desc='Event Time', message='b', timestamp=2, evidence_path=prov.evidence_path)\n"
        "    yield Event(data_type='t', timestamp_desc='Event Time', message='a', timestamp=1, evidence_path=prov.evidence_path)\n"
        "def net(path, prov):\n"
        "    socket.create_connection(('example.com', 80))\n"
        "    yield from ()\n"
        "def crash(path, prov):\n"
        "    raise ValueError('malformed record at 0x10')\n"
        "def slow(path, prov):\n"
        "    time.sleep(30)\n"
        "    yield from ()\n"
        "def hog(path, prov):\n"
        "    x = bytearray(1024 * 1024 * 1024)\n"
        "    yield from ()\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    for n in ("good", "net", "crash", "slow", "hog"):
        monkeypatch.setitem(runner.PY_PARSERS, f"fake_{n}", ("fakeparsers", n))
    # The child process re-imports runner, so also expose the mapping through a module the child can read.
    (tmp_path / "sitecustomize.py").write_text(
        "from veritas.pipeline import runner\n" + "".join(f"runner.PY_PARSERS['fake_{n}'] = ('fakeparsers', '{n}')\n" for n in ("good", "net", "crash", "slow", "hog")),
        encoding="utf-8",
    )
    ev = tmp_path / "evidence.bin"
    ev.write_bytes(b"x")
    return ev


def _run(name, ev, **kw):
    # Pre-register via a bootstrap import of sitecustomize in the child.
    return run_parser(name, ev, "a" * 64, "C:/x", limits=Limits(**kw), extra_args=[])


def test_worker_isolation(fake_parser, monkeypatch):
    # The child imports sitecustomize only when run without -I; inject registration through runner instead.
    monkeypatch.setattr(runner, "PY_PARSERS", runner.PY_PARSERS)
    import veritas.pipeline.worker as w

    boot = w._CHILD_BOOTSTRAP
    monkeypatch.setattr(w, "_CHILD_BOOTSTRAP", "import sitecustomize\n" + boot)
    ok = _run("fake_good", fake_parser)
    assert ok.ok and [e.message for e in ok.events] == ["a", "b"]
    assert all(e.evidence_sha256 == "a" * 64 for e in ok.events)
    net = _run("fake_net", fake_parser)
    assert not net.ok and "network" in (net.error or "").lower()
    crash = _run("fake_crash", fake_parser)
    assert not crash.ok and "malformed record" in crash.error
    slow = _run("fake_slow", fake_parser, timeout_s=2)
    assert not slow.ok and slow.killed == "timeout"
    hog = _run("fake_hog", fake_parser, memory_mb=256)
    assert not hog.ok
    unknown = _run("does_not_exist", fake_parser)
    assert not unknown.ok and "unknown parser" in unknown.error
    assert describe_limits(Limits())["network"] is False


def test_runner_usage_error(capsys):
    assert runner.main([]) == 2
    assert json.loads(capsys.readouterr().err.splitlines()[0])["level"] == "error"
