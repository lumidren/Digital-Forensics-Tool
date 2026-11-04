"""Per-evidence processing DAG with idempotent, resumable steps.

A job is a set of named steps with dependencies. Each step's identity is
``sha256(evidence_sha256 | step | parser_version | params)``; when a step with that key already
completed, its stored output digest is reused and the step is skipped. State lives in SQLite (native
profile) or Postgres (cluster profile) through :class:`JobStore`, so a crashed or restarted worker
resumes at the first incomplete step. Steps are scheduled by priority (lower number first), then by
enqueue order.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

PENDING, RUNNING, DONE, FAILED, SKIPPED = "pending", "running", "done", "failed", "skipped"

PRIORITY = {"triage": 10, "memory": 20, "logs": 30, "cloud": 30, "mobile": 40, "disk": 50, "carve": 90}


def step_key(evidence_sha256: str, step: str, version: str, params: dict[str, Any]) -> str:
    payload = json.dumps([evidence_sha256, step, version, params], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class Step:
    name: str
    fn: Callable[["StepContext"], dict[str, Any]]
    deps: list[str] = field(default_factory=list)
    version: str = "1"
    params: dict[str, Any] = field(default_factory=dict)
    retries: int = 1


@dataclass(slots=True)
class StepContext:
    job_id: str
    case_id: str
    evidence_sha256: str
    step: str
    inputs: dict[str, dict[str, Any]]
    progress: Callable[[float, str], None]


class JobStore:
    """Job and step state, shared by every API and worker process of a deployment.

    ``target`` is a filesystem path (SQLite, native profile) or a SQLAlchemy URL such as
    ``postgresql+psycopg://...`` (cluster profile). Claiming is an atomic compare-and-set
    (``UPDATE ... WHERE job_id = :id AND <claimable>``; exactly one worker sees ``rowcount == 1``),
    so any number of worker processes can poll the same table. A claim is a lease: the holder
    refreshes ``lease_until`` on every progress report, and a job whose lease expired (worker
    crashed or was evicted) becomes claimable again and resumes at its first incomplete step.
    """

    LEASE_S = 900

    def __init__(self, target: str | Path, worker_id: str | None = None):
        import os
        import socket

        from sqlalchemy import create_engine, event

        url = str(target) if "://" in str(target) else f"sqlite:///{Path(target).as_posix()}"
        self._sqlite = url.startswith("sqlite")
        self._engine = create_engine(url, future=True, pool_pre_ping=True, connect_args={"check_same_thread": False, "timeout": 30} if self._sqlite else {})
        if self._sqlite:
            @event.listens_for(self._engine, "connect")
            def _wal(conn, _):  # pragma: no cover - trivial
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA busy_timeout=30000")

        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{threading.get_ident()}"
        self._lock = threading.Lock()
        ddl = [
            "CREATE TABLE IF NOT EXISTS jobs(job_id VARCHAR(64) PRIMARY KEY, case_id VARCHAR(64), evidence_sha256 VARCHAR(64), kind VARCHAR(32), "
            "priority INTEGER, state VARCHAR(16), created VARCHAR(32), updated VARCHAR(32), error TEXT, claimed_by VARCHAR(200), lease_until VARCHAR(32))",
            "CREATE TABLE IF NOT EXISTS steps(job_id VARCHAR(64), name VARCHAR(100), step_key VARCHAR(64), state VARCHAR(16), attempts INTEGER, progress REAL, "
            "message TEXT, output TEXT, started VARCHAR(32), finished VARCHAR(32), duration_ms INTEGER, PRIMARY KEY(job_id, name))",
            "CREATE TABLE IF NOT EXISTS step_cache(step_key VARCHAR(64) PRIMARY KEY, output TEXT, finished VARCHAR(32))",
            "CREATE INDEX IF NOT EXISTS ix_jobs_state ON jobs(state, priority, created)",
        ]
        with self._engine.begin() as c:
            for stmt in ddl:
                c.exec_driver_sql(stmt)

    def _x(self, sql: str, **params: Any):
        from sqlalchemy import text

        with self._engine.begin() as c:
            return c.execute(text(sql), params)

    def _rows(self, sql: str, **params: Any) -> list[tuple]:
        from sqlalchemy import text

        with self._engine.connect() as c:
            return [tuple(r) for r in c.execute(text(sql), params)]

    @staticmethod
    def _now(offset_s: int = 0) -> str:
        return datetime.fromtimestamp(time.time() + offset_s, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def create_job(self, job_id: str, case_id: str, evidence_sha256: str, kind: str) -> None:
        if self._rows("SELECT 1 FROM jobs WHERE job_id = :j", j=job_id):
            return
        self._x("INSERT INTO jobs(job_id, case_id, evidence_sha256, kind, priority, state, created, updated) VALUES(:j, :c, :e, :k, :p, :s, :t, :t)",
                j=job_id, c=case_id, e=evidence_sha256, k=kind, p=PRIORITY.get(kind, 50), s=PENDING, t=self._now())

    def set_job(self, job_id: str, state: str, error: str | None = None) -> None:
        release = ", claimed_by = NULL, lease_until = NULL" if state != RUNNING else ""
        self._x("UPDATE jobs SET state = :s, updated = :t, error = :e" + release + " WHERE job_id = :j", s=state, t=self._now(), e=error, j=job_id)  # nosec B608 - constant SQL fragments only; values are bound parameters

    def claim(self, job_id: str) -> bool:
        """Atomically take ``job_id`` if it is pending or its lease expired."""
        now = self._now()
        res = self._x(
            "UPDATE jobs SET state = :run, claimed_by = :w, lease_until = :lease, updated = :now WHERE job_id = :j AND "
            "(state = :pend OR (state = :run AND (lease_until IS NULL OR lease_until < :now)))",
            run=RUNNING, w=self.worker_id, lease=self._now(self.LEASE_S), now=now, j=job_id, pend=PENDING,
        )
        return res.rowcount == 1

    def next_job(self) -> tuple[str, str, str, str] | None:
        """Claim and return the highest-priority claimable job, or None."""
        for _ in range(20):
            rows = self._rows(
                "SELECT job_id, case_id, evidence_sha256, kind FROM jobs WHERE state = :pend OR (state = :run AND (lease_until IS NULL OR lease_until < :now)) "
                "ORDER BY priority, created LIMIT 5",
                pend=PENDING, run=RUNNING, now=self._now(),
            )
            if not rows:
                return None
            for r in rows:
                if self.claim(r[0]):
                    return r  # type: ignore[return-value]
        return None

    def renew(self, job_id: str) -> None:
        self._x("UPDATE jobs SET lease_until = :lease WHERE job_id = :j AND claimed_by = :w", lease=self._now(self.LEASE_S), j=job_id, w=self.worker_id)

    def queue_depth(self) -> int:
        return int(self._rows("SELECT COUNT(*) FROM jobs WHERE state IN (:a, :b)", a=PENDING, b=RUNNING)[0][0])

    def job(self, job_id: str) -> dict[str, Any] | None:
        r = self._rows("SELECT job_id, case_id, evidence_sha256, kind, priority, state, created, updated, error, claimed_by FROM jobs WHERE job_id = :j", j=job_id)
        if not r:
            return None
        steps = [
            {"name": s[0], "state": s[1], "attempts": s[2], "progress": s[3], "message": s[4], "duration_ms": s[5]}
            for s in self._rows("SELECT name, state, attempts, progress, message, duration_ms FROM steps WHERE job_id = :j ORDER BY started, name", j=job_id)
        ]
        keys = ("job_id", "case_id", "evidence_sha256", "kind", "priority", "state", "created", "updated", "error", "claimed_by")
        return dict(zip(keys, r[0])) | {"steps": steps}

    def jobs_for_case(self, case_id: str) -> list[dict[str, Any]]:
        ids = [r[0] for r in self._rows("SELECT job_id FROM jobs WHERE case_id = :c ORDER BY created", c=case_id)]
        return [j for j in (self.job(i) for i in ids) if j]

    def step_state(self, job_id: str, name: str) -> str | None:
        r = self._rows("SELECT state FROM steps WHERE job_id = :j AND name = :n", j=job_id, n=name)
        return r[0][0] if r else None

    def reset_failed_steps(self, job_id: str) -> None:
        self._x("UPDATE steps SET state = :p WHERE job_id = :j AND state IN (:f, :s)", p=PENDING, j=job_id, f=FAILED, s=SKIPPED)

    def step_output(self, job_id: str, name: str) -> dict[str, Any]:
        r = self._rows("SELECT output FROM steps WHERE job_id = :j AND name = :n", j=job_id, n=name)
        return json.loads(r[0][0]) if r and r[0][0] else {}

    def cached(self, key: str) -> dict[str, Any] | None:
        r = self._rows("SELECT output FROM step_cache WHERE step_key = :k", k=key)
        return json.loads(r[0][0]) if r else None

    def begin_step(self, job_id: str, name: str, key: str) -> int:
        with self._lock:
            existing = self._rows("SELECT attempts FROM steps WHERE job_id = :j AND name = :n", j=job_id, n=name)
            if existing:
                self._x("UPDATE steps SET state = :s, attempts = attempts + 1, started = :t, step_key = :k WHERE job_id = :j AND name = :n",
                        s=RUNNING, t=self._now(), k=key, j=job_id, n=name)
                return int(existing[0][0]) + 1
            self._x("INSERT INTO steps(job_id, name, step_key, state, attempts, progress, started) VALUES(:j, :n, :k, :s, 1, 0, :t)",
                    j=job_id, n=name, k=key, s=RUNNING, t=self._now())
            return 1

    def progress(self, job_id: str, name: str, fraction: float, message: str) -> None:
        self._x("UPDATE steps SET progress = :p, message = :m WHERE job_id = :j AND name = :n", p=max(0.0, min(1.0, fraction)), m=message[:500], j=job_id, n=name)
        self.renew(job_id)

    def finish_step(self, job_id: str, name: str, key: str, state: str, output: dict[str, Any], message: str, duration_ms: int) -> None:
        out = json.dumps(output, sort_keys=True)
        with self._lock:
            self._x("UPDATE steps SET state = :s, output = :o, message = :m, progress = :p, finished = :t, duration_ms = :d WHERE job_id = :j AND name = :n",
                    s=state, o=out, m=message[:2000], p=1.0 if state in (DONE, SKIPPED) else 0.0, t=self._now(), d=duration_ms, j=job_id, n=name)
            if state == DONE:
                self._x("DELETE FROM step_cache WHERE step_key = :k", k=key)
                self._x("INSERT INTO step_cache(step_key, output, finished) VALUES(:k, :o, :t)", k=key, o=out, t=self._now())
        self.renew(job_id)


class Dag:
    def __init__(self, steps: list[Step]):
        names = {s.name for s in steps}
        for s in steps:
            for d in s.deps:
                if d not in names:
                    raise ValueError(f"step {s.name} depends on unknown step {d}")
        self.steps = {s.name: s for s in steps}
        self.order = self._toposort()

    def _toposort(self) -> list[str]:
        indeg = {n: len(s.deps) for n, s in self.steps.items()}
        children: dict[str, list[str]] = {n: [] for n in self.steps}
        for n, s in self.steps.items():
            for d in s.deps:
                children[d].append(n)
        ready = sorted(n for n, k in indeg.items() if k == 0)
        order: list[str] = []
        while ready:
            n = ready.pop(0)
            order.append(n)
            for c in sorted(children[n]):
                indeg[c] -= 1
                if indeg[c] == 0:
                    ready.append(c)
            ready.sort()
        if len(order) != len(self.steps):
            raise ValueError("dependency cycle in DAG")
        return order


ProgressSink = Callable[[dict[str, Any]], None]


def execute(dag: Dag, store: JobStore, job_id: str, case_id: str, evidence_sha256: str, sink: ProgressSink | None = None) -> str:
    """Run (or resume) every step of ``dag`` for one job. Returns the final job state."""
    store.set_job(job_id, RUNNING)
    failed: set[str] = set()
    for name in dag.order:
        step = dag.steps[name]
        if store.step_state(job_id, name) in (DONE, SKIPPED):
            continue
        if any(d in failed for d in step.deps):
            key = step_key(evidence_sha256, name, step.version, step.params)
            store.begin_step(job_id, name, key)
            store.finish_step(job_id, name, key, SKIPPED, {}, "dependency failed", 0)
            failed.add(name)
            continue
        key = step_key(evidence_sha256, name, step.version, step.params)
        cached = store.cached(key)
        store.begin_step(job_id, name, key)
        if cached is not None:
            store.finish_step(job_id, name, key, DONE, cached, "reused cached result", 0)
            if sink:
                sink({"job_id": job_id, "step": name, "state": DONE, "progress": 1.0, "cached": True})
            continue
        inputs = {d: store.step_output(job_id, d) for d in step.deps}

        def progress(frac: float, msg: str, _name: str = name) -> None:
            store.progress(job_id, _name, frac, msg)
            if sink:
                sink({"job_id": job_id, "step": _name, "state": RUNNING, "progress": round(frac, 4), "message": msg})

        attempt = 0
        while True:
            attempt += 1
            t0 = time.monotonic()
            try:
                out = step.fn(StepContext(job_id, case_id, evidence_sha256, name, inputs, progress)) or {}
                store.finish_step(job_id, name, key, DONE, out, "ok", int((time.monotonic() - t0) * 1000))
                if sink:
                    sink({"job_id": job_id, "step": name, "state": DONE, "progress": 1.0})
                break
            except Exception as exc:
                msg = f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=5)}"
                if attempt <= step.retries:
                    store.begin_step(job_id, name, key)
                    continue
                store.finish_step(job_id, name, key, FAILED, {}, msg, int((time.monotonic() - t0) * 1000))
                failed.add(name)
                if sink:
                    sink({"job_id": job_id, "step": name, "state": FAILED, "error": str(exc)[:500]})
                break
    state = FAILED if failed else DONE
    store.set_job(job_id, state, ", ".join(sorted(failed)) or None)
    return state
