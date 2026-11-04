"""Evidence classification and per-evidence DAG construction; the native-profile queue loop.

``plan(kind, head)`` decides which steps an evidence object needs. Each parse step:

1. records a signed ``access`` custody entry for the evidence (THREAT:T1.4);
2. materializes the object (plaintext copy if the store is encrypted) into a private temp dir;
3. runs the parser in the sandboxed worker;
4. normalizes timezone / skew with the evidence's clock model and ingests into the timeline.

Disk images get a ``harvest`` step that extracts known artifacts; each harvested artifact is
stored as a derived object, recorded as a ``transform`` custody entry, and parsed in a child step.
Afterwards the findings engine runs once per job.
"""
from __future__ import annotations

import json
import logging
import shutil
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from ..timeline.skew import HostClock, normalize
from .dag import Dag, JobStore, Step, StepContext, execute
from .worker import Limits, run_parser

log = logging.getLogger("veritas.pipeline")

PARSER_VERSION = "0.1.0"

MAGIC: list[tuple[int, bytes, str]] = [
    (0, b"EVF\x09\x0d\x0a\xff\x00", "disk"),
    (0, b"ElfFile\x00", "evtx"),
    (4, b"LfLe", "evt"),
    (4, b"SCCA", "prefetch"),
    (0, b"MAM\x04", "prefetch"),
    (0, b"regf", "regf-events"),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "olecf"),
    (0, b"LPKSHHRH", "journald"),
    (0, b"bplist00", "plist"),
    (0, b"\xd4\xc3\xb2\xa1", "pcap"),
    (0, b"\xa1\xb2\xc3\xd4", "pcap"),
    (0, b"\x0a\x0d\x0d\x0a", "pcap"),
    (0, b"FILE0", "mft"),  # raw $MFT extract: first record signature
    (0, b"MZ", "pe"),
    (0, b"\x7fELF", "pe"),
    (0, b"SQLite format 3\x00", "auto"),
    (0, b"ANDROID BACKUP\n", "android_backup"),
    (0, b"!BDN", "auto"),  # PST/OST
]


def classify(head: bytes, declared_kind: str | None, name: str = "") -> str:
    if declared_kind == "memory":
        return "memory"
    if declared_kind == "cloud":
        return "cloud"
    if declared_kind == "mobile" and Path(name).suffix.lower() != ".ab":
        return "ios_backup"
    for off, sig, kind in MAGIC:
        if head[off:off + len(sig)] == sig:
            if kind == "olecf":
                return "jumplist" if "destinations-ms" in name.lower() else "auto"
            return kind
    if head[:2] == b"PK":
        return "triage" if declared_kind == "triage" else "auto"
    if len(head) >= 512 and head[510:512] == b"\x55\xaa" or head[3:11] in (b"NTFS    ", b"EXFAT   ") or head[1080:1082] == b"\x53\xef" or head[32:36] == b"NXSB":
        return "disk"
    if declared_kind == "disk":
        return "disk"
    stripped = head.lstrip()
    if stripped.startswith((b"{", b"[")) and (b'"Records"' in head or b'"eventVersion"' in head or b'"CreationTime"' in head or b'"activityDateTime"' in head or b'"id":{"time"' in head.replace(b" ", b"")):
        return "cloud"
    if stripped.startswith(b"<?xml") and b"<plist" in head:
        return "plist"
    if stripped.startswith(b"<?xml") and b"<Task" in head:
        return "taskxml"
    return "auto"


ProgressSink = Callable[[dict[str, Any]], None]


class Processor:
    """Builds and runs DAGs for evidence objects. Owns no global state beyond ``ctx``."""

    def __init__(self, ctx, jobs: JobStore, sink: ProgressSink | None = None, limits: Limits | None = None):
        self.ctx = ctx
        self.jobs = jobs
        self.sink = sink
        self.limits = limits or Limits()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ helpers used by steps
    def _clock(self, ev) -> HostClock:
        return HostClock(ev.sha256, ev.tz_name, int(ev.clock_skew_ms or 0) * 1_000_000)

    def _materialize_evidence(self, ev, tmp: Path) -> Path:
        """Primary object plus any further segments (E02, ...) side by side under their original names."""
        path = self.ctx.store.materialize(ev.sha256, tmp, ev.name)
        for seg in ev.segments or []:
            self.ctx.store.materialize(seg["sha256"], tmp, seg["name"])
        return path

    def _parse_object(self, case_id: str, evidence_id: str, address: str, logical: str, parser: str, clock: HostClock, step: StepContext, extra: list[str] | None = None, ev=None) -> dict[str, Any]:
        self.ctx.custody(case_id, "veritas-pipeline", "access", f"parse with {parser}", evidence_id=evidence_id,
                         details={"object_sha256": address, "parser": parser, "parser_version": PARSER_VERSION, "logical_path": logical, "job_id": step.job_id})
        tmp = Path(tempfile.mkdtemp(prefix="veritas-mat-"))
        try:
            if ev is not None and ev.segments:
                path = self._materialize_evidence(ev, tmp)
            else:
                path = self.ctx.store.materialize(address, tmp, Path(logical).name if logical else None)
            res = run_parser(parser, path, address, logical, self.limits, extra)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if not res.ok:
            raise RuntimeError(f"{parser} failed on {logical or address}: {res.error}")
        events = list(normalize(res.events, {address: clock}))
        for e in events:
            if not e.evidence_path:
                e.evidence_path = logical
        n = self.ctx.timeline.ingest(case_id, events)
        from ..api import observability as obs

        obs.PARSER_EVENTS.labels(parser).inc(len(events))
        obs.BYTES_PROCESSED.inc(int(self.ctx.store.meta(address).hashes.length))
        obs.TIMELINE_EVENTS.labels(case_id).set(self.ctx.timeline.count(case_id))
        return {"parser": parser, "events": len(events), "ingested": n, "warnings": res.warnings[:50], "duration_ms": res.duration_ms}

    def build_dag(self, case_id: str, ev, kind: str) -> Dag:
        clock = self._clock(ev)
        steps: list[Step] = []

        def verify_step(step: StepContext) -> dict[str, Any]:
            step.progress(0.0, "re-hashing evidence")
            objects = [ev.sha256] + [s["sha256"] for s in (ev.segments or [])]
            for i, address in enumerate(objects):
                step.progress(i / len(objects), f"re-hashing object {i + 1} of {len(objects)}")
                if not self.ctx.store.verify(address):
                    raise RuntimeError(f"stored object {address} no longer matches its acquisition hash")
            return {"verified": True, "objects": len(objects)}

        steps.append(Step("verify", verify_step, version="1"))

        if kind == "disk":
            def fs_timeline(step: StepContext) -> dict[str, Any]:
                return self._parse_object(case_id, ev.id, ev.sha256, ev.name, "fs-events", clock, step, ev=ev)

            def harvest(step: StepContext) -> dict[str, Any]:
                return self._harvest(case_id, ev, clock, step)

            steps += [Step("fs_timeline", fs_timeline, ["verify"], PARSER_VERSION), Step("harvest", harvest, ["verify"], PARSER_VERSION)]
        elif kind == "triage":
            steps.append(Step("triage_bundle", lambda step: self._triage(case_id, ev, clock, step), ["verify"], PARSER_VERSION))
        else:
            parser = kind
            steps.append(Step(f"parse_{parser}", lambda step: self._parse_object(case_id, ev.id, ev.sha256, ev.name, parser, clock, step), ["verify"], PARSER_VERSION, {"parser": parser}))
        last = [s.name for s in steps if s.name != "verify"]
        steps.append(Step("analytics", lambda step: self._analytics(case_id, step), last, PARSER_VERSION, {"case_id": case_id, "evidence": ev.sha256}))
        return Dag(steps)

    def _ingest_derived(self, case_id: str, parent, path: Path, logical: str) -> str:
        meta = self.ctx.store.put_file(case_id, path, Path(logical).name)
        self.ctx.custody(case_id, "veritas-pipeline", "transform", f"artifact extracted from {parent.id}", evidence_id=parent.id,
                         hashes={"md5": meta.hashes.md5, "sha256": meta.hashes.sha256, "sha3_256": meta.hashes.sha3_256, "length": meta.hashes.length},
                         details={"parent_sha256": parent.sha256, "logical_path": logical})
        return meta.address

    def _harvest(self, case_id: str, ev, clock: HostClock, step: StepContext) -> dict[str, Any]:
        from .runner import find_binary

        exe = find_binary("fs-tool")
        if exe is None:
            raise FileNotFoundError("fs-tool binary not found; build the Rust workspace")
        self.ctx.custody(case_id, "veritas-pipeline", "access", "harvest artifacts from image", evidence_id=ev.id, details={"tool": "fs-tool harvest", "job_id": step.job_id})
        tmp = Path(tempfile.mkdtemp(prefix="veritas-harvest-"))
        try:
            img = self._materialize_evidence(ev, tmp)
            out = tmp / "out"
            import subprocess

            proc = subprocess.run([exe, "harvest", str(img), "--out", str(out)], capture_output=True, timeout=self.limits.timeout_s)
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.decode("utf-8", "replace")[-2000:])
            manifest = [json.loads(l) for l in (out / "manifest.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
            results: dict[str, Any] = {"artifacts": len(manifest), "stored": 0, "parsed": 0, "preserved_only": 0, "failed": []}
            out_root = out.resolve()
            for i, item in enumerate(manifest):
                step.progress(i / max(1, len(manifest)), f"parsing {item['path']}")
                # `output` is the escaped location fs-tool wrote, relative to --out.
                local = (out / item.get("output", f"{item['partition']}/{item['path'].lstrip('/')}")).resolve()
                if not str(local).startswith(str(out_root)) or not local.is_file():
                    results["failed"].append({"path": item["path"], "error": "harvested file missing or outside the output directory"})
                    continue
                logical = f"p{item['partition']}:{item['path']}" if item.get("partition") else item["path"]
                address = self._ingest_derived(case_id, ev, local, logical)
                results["stored"] += 1
                kind = classify(local.open("rb").read(4096), None, item["path"])
                lower_name = Path(item["path"]).name.lower()
                if item.get("kind") == "registry" and lower_name.endswith((".log", ".log1", ".log2")):
                    # Registry transaction logs are preserved with their hive; they are not hives.
                    results["preserved_only"] += 1
                    continue
                if item.get("kind") == "ntfs_meta":
                    name = Path(item["path"]).name.lower()
                    if name == "$mft":
                        # Already covered by this image's fs_timeline step; preserved, not re-parsed,
                        # so file events are not duplicated under a second evidence hash.
                        results["preserved_only"] += 1
                        continue
                    kind = {"$j": "usn", "$usnjrnl:$j": "usn", "$logfile": "logfile"}.get(name, kind)
                try:
                    r = self._parse_object(case_id, ev.id, address, item["path"], kind, clock, step)
                    results["parsed"] += 1
                except Exception as exc:  # one bad artifact never fails the image
                    results["failed"].append({"path": item["path"], "error": str(exc)[:300]})
            return results
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _triage(self, case_id: str, ev, clock: HostClock, step: StepContext) -> dict[str, Any]:
        import zipfile

        tmp = Path(tempfile.mkdtemp(prefix="veritas-triage-"))
        try:
            src = self.ctx.store.materialize(ev.sha256, tmp, ev.name)
            self.ctx.custody(case_id, "veritas-pipeline", "access", "unpack triage bundle", evidence_id=ev.id, details={"job_id": step.job_id})
            out = tmp / "x"
            parsed, failed = 0, []
            with zipfile.ZipFile(src) as z:
                manifest = json.loads(z.read("manifest.json")) if "manifest.json" in z.namelist() else None
                names = [n for n in z.namelist() if not n.endswith("/") and n != "manifest.json"]
                expected = {f["path"]: f["sha256"] for f in (manifest or {}).get("files", [])}
                for i, n in enumerate(sorted(names)):
                    target = (out / n).resolve()
                    if not str(target).startswith(str(out.resolve())):
                        failed.append({"path": n, "error": "path traversal rejected"})
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(n) as zf, open(target, "wb") as fh:
                        shutil.copyfileobj(zf, fh)
                    address = self._ingest_derived(case_id, ev, target, n)
                    if n in expected and expected[n] != address:
                        failed.append({"path": n, "error": "sha256 differs from bundle manifest"})
                        continue
                    step.progress(i / max(1, len(names)), f"parsing {n}")
                    kind = classify(target.open("rb").read(4096), None, n)
                    try:
                        self._parse_object(case_id, ev.id, address, n, kind, clock, step)
                        parsed += 1
                    except Exception as exc:
                        failed.append({"path": n, "error": str(exc)[:300]})
            return {"files": len(names), "parsed": parsed, "failed": failed}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _analytics(self, case_id: str, step: StepContext) -> dict[str, Any]:
        from ..api.findings import run_rules

        step.progress(0.1, "running analytics rules")
        n = run_rules(self.ctx, case_id)
        return {"proposed": n}

    # ------------------------------------------------------------------ queue
    def enqueue(self, case_id: str, ev, kind: str) -> str:
        job_id = f"J-{uuid.uuid4().hex[:12]}"
        self.jobs.create_job(job_id, case_id, ev.sha256, kind)
        return job_id

    def run_job(self, job_id: str) -> str:
        from ..api.db import Evidence

        job = self.jobs.job(job_id)
        if job is None:
            raise KeyError(job_id)
        with self.ctx.Session() as s:
            ev = s.query(Evidence).filter_by(case_id=job["case_id"], sha256=job["evidence_sha256"]).first()
            if ev is None:
                raise KeyError("evidence for job not found")
            s.expunge(ev)
        dag = self.build_dag(job["case_id"], ev, job["kind"])
        self._set_status(ev.id, "processing")
        state = execute(dag, self.jobs, job_id, job["case_id"], ev.sha256, self.sink)
        self._set_status(ev.id, "processed" if state == "done" else "failed")
        return state

    def _set_status(self, evidence_id: str, status: str) -> None:
        from ..api.db import Evidence

        with self.ctx.Session() as s:
            ev = s.get(Evidence, evidence_id)
            if ev:
                ev.status = status
                s.commit()

    def loop(self, poll_s: float = 1.0) -> None:
        while not self._stop.is_set():
            nxt = self.jobs.next_job()
            if nxt is None:
                self._stop.wait(poll_s)
                continue
            try:
                self.run_job(nxt[0])
            except Exception as exc:
                log.exception("job %s crashed", nxt[0])
                self.jobs.set_job(nxt[0], "failed", str(exc)[:500])

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self.loop, name="veritas-processor", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()


def main() -> None:
    """Standalone worker process for the cluster profile (``veritas-worker``)."""
    from ..api.config import load
    from ..api.context import AppContext

    logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')
    ctx = AppContext(load())
    import os

    from prometheus_client import start_http_server

    # Worker pods expose /metrics on their own port (scraped by the ServiceMonitor).
    start_http_server(int(os.environ.get("VERITAS_METRICS_PORT", "9102")))
    p = Processor(ctx, JobStore(os.environ.get("VERITAS_JOBS_URL") or ctx.settings.data_dir / "jobs.db"))
    try:
        p.loop()
    except KeyboardInterrupt:
        p.stop()
        time.sleep(0.1)
