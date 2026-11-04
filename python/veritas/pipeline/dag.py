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
import sqlite3
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
    def __init__(self, path: str | Path):
        self._conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS jobs(job_id TEXT PRIMARY KEY, case_id TEXT, evidence_sha256 TEXT, kind TEXT, priority INTEGER,
              state TEXT, created TEXT, updated TEXT, error TEXT);
            CREATE TABLE IF NOT EXISTS steps(job_id TEXT, name TEXT, key TEXT, state TEXT, attempts INTEGER, progress REAL, message TEXT,
              output TEXT, started TEXT, finished TEXT, duration_ms INTEGER, PRIMARY KEY(job_id, name));
            CREATE TABLE IF NOT EXISTS step_cache(key TEXT PRIMARY KEY, output TEXT, finished TEXT);
            CREATE INDEX IF NOT EXISTS ix_jobs_state ON jobs(state, priority, created);
            """
        )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def create_job(self, job_id: str, case_id: str, evidence_sha256: str, kind: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO jobs VALUES(?,?,?,?,?,?,?,?,NULL)",
                (job_id, case_id, evidence_sha256, kind, PRIORITY.get(kind, 50), PENDING, self._now(), self._now()),
            )

    def set_job(self, job_id: str, state: str, error: str | None = None) -> None:
        with self._lock:
            self._conn.execute("UPDATE jobs SET state=?, updated=?, error=? WHERE job_id=?", (state, self._now(), error, job_id))

    def next_job(self) -> tuple[str, str, str, str] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT job_id, case_id, evidence_sha256, kind FROM jobs WHERE state IN (?, ?) ORDER BY priority, created LIMIT 1", (PENDING, RUNNING)
            ).fetchone()
            return tuple(row) if row else None  # type: ignore[return-value]

    def queue_depth(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM jobs WHERE state IN (?, ?)", (PENDING, RUNNING)).fetchone()[0])

    def job(self, job_id: str) -> dict[str, Any] | None:
        r = self._conn.execute("SELECT job_id, case_id, evidence_sha256, kind, priority, state, created, updated, error FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if not r:
            return None
        steps = [
            {"name": s[0], "state": s[1], "attempts": s[2], "progress": s[3], "message": s[4], "duration_ms": s[5]}
            for s in self._conn.execute("SELECT name, state, attempts, progress, message, duration_ms FROM steps WHERE job_id=? ORDER BY started, name", (job_id,))
        ]
        return dict(zip(("job_id", "case_id", "evidence_sha256", "kind", "priority", "state", "created", "updated", "error"), r)) | {"steps": steps}

    def jobs_for_case(self, case_id: str) -> list[dict[str, Any]]:
        ids = [r[0] for r in self._conn.execute("SELECT job_id FROM jobs WHERE case_id=? ORDER BY created", (case_id,))]
        return [j for j in (self.job(i) for i in ids) if j]

    def step_state(self, job_id: str, name: str) -> str | None:
        r = self._conn.execute("SELECT state FROM steps WHERE job_id=? AND name=?", (job_id, name)).fetchone()
        return r[0] if r else None

    def step_output(self, job_id: str, name: str) -> dict[str, Any]:
        r = self._conn.execute("SELECT output FROM steps WHERE job_id=? AND name=?", (job_id, name)).fetchone()
        return json.loads(r[0]) if r and r[0] else {}

    def cached(self, key: str) -> dict[str, Any] | None:
        r = self._conn.execute("SELECT output FROM step_cache WHERE key=?", (key,)).fetchone()
        return json.loads(r[0]) if r else None

    def begin_step(self, job_id: str, name: str, key: str) -> int:
        with self._lock:
            self._conn.execute(
                "INSERT INTO steps(job_id, name, key, state, attempts, progress, started) VALUES(?,?,?,?,1,0,?) "
                "ON CONFLICT(job_id, name) DO UPDATE SET state=excluded.state, attempts=steps.attempts+1, started=excluded.started, key=excluded.key",
                (job_id, name, key, RUNNING, self._now()),
            )
            return int(self._conn.execute("SELECT attempts FROM steps WHERE job_id=? AND name=?", (job_id, name)).fetchone()[0])

    def progress(self, job_id: str, name: str, fraction: float, message: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE steps SET progress=?, message=? WHERE job_id=? AND name=?", (max(0.0, min(1.0, fraction)), message[:500], job_id, name))

    def finish_step(self, job_id: str, name: str, key: str, state: str, output: dict[str, Any], message: str, duration_ms: int) -> None:
        out = json.dumps(output, sort_keys=True)
        with self._lock:
            self._conn.execute(
                "UPDATE steps SET state=?, output=?, message=?, progress=?, finished=?, duration_ms=? WHERE job_id=? AND name=?",
                (state, out, message[:2000], 1.0 if state in (DONE, SKIPPED) else 0.0, self._now(), duration_ms, job_id, name),
            )
            if state == DONE:
                self._conn.execute("INSERT OR REPLACE INTO step_cache VALUES(?,?,?)", (key, out, self._now()))


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
