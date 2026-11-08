"""Retention disposal: plan (dry run) and execute the destruction of a case past its retention date.

The order of a real disposal is fixed and every step is recorded:

1. a signed custody ``note`` entry (purpose ``"retention disposal"``) listing every object address
   and hash about to be destroyed, followed by an anchor of the ledger head;
2. timeline events, store objects not referenced by another live case, report files, intake
   leftovers, pending jobs and the case's database rows are removed;
3. a closing ``note`` with the per-object outcome, a second anchor, and the case row is marked
   ``status="disposed"``.

The custody ledger, its anchors and the audit log are never deleted: they are the proof of what
existed and that it was destroyed. THREAT:T1.3 (WORM is only lifted here, for one address at a time).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException

from ..pipeline.dag import FAILED, PENDING, RUNNING, JobStore
from ..store.content import LocalStore, StoreError
from .db import Bookmark, Case, Evidence, FindingRow, Hypothesis, IocRow, Membership, Note, Report, SavedView, Task

if TYPE_CHECKING:
    from .context import AppContext

PURPOSE = "retention disposal"
DISPOSED = "disposed"

# Case-scoped tables removed on disposal (memberships handled separately: leads are kept so that the
# retained custody ledger stays reachable through GET /custody and /custody/verify).
_TABLES: dict[str, Any] = {
    "evidence": Evidence, "findings": FindingRow, "bookmarks": Bookmark, "notes": Note, "hypotheses": Hypothesis,
    "tasks": Task, "iocs": IocRow, "views": SavedView, "reports": Report,
}


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _derived_from_ledger(ctx: AppContext, case_id: str) -> set[str]:
    """Addresses of artifacts the pipeline extracted and stored for this case (custody ``transform``)."""
    out = set()
    for e in ctx.ledger(case_id).entries():
        if e.get("kind") == "transform" and (e.get("details") or {}).get("parent_sha256") and (e.get("hashes") or {}).get("sha256"):
            out.add(e["hashes"]["sha256"])
    return out


def _evidence_addresses(ev: Evidence) -> list[tuple[str, str]]:
    return [(ev.sha256, "primary")] + [(s["sha256"], "segment") for s in (ev.segments or []) if s.get("sha256")]


def live_references(ctx: AppContext, exclude: set[str]) -> dict[str, set[str]]:
    """address -> ids of non-disposed cases (outside ``exclude``) that still reference it."""
    refs: dict[str, set[str]] = {}
    with ctx.Session() as s:
        live = [c.id for c in s.query(Case) if c.status != DISPOSED and c.id not in exclude]
        for ev in s.query(Evidence).filter(Evidence.case_id.in_(live)) if live else []:
            for a, _ in _evidence_addresses(ev):
                refs.setdefault(a, set()).add(ev.case_id)
    for cid in live:
        for a in _derived_from_ledger(ctx, cid):
            refs.setdefault(a, set()).add(cid)
    return refs


def _object_info(ctx: AppContext, address: str) -> dict[str, Any]:
    try:
        m = ctx.store.meta(address)
        info: dict[str, Any] = {"address": address, "sha256": m.hashes.sha256, "md5": m.hashes.md5, "sha3_256": m.hashes.sha3_256,
                                "size": m.hashes.length, "encrypted": m.encrypted, "present": True}
    except (StoreError, OSError, KeyError, ValueError):
        info = {"address": address, "sha256": address, "md5": None, "sha3_256": None, "size": 0, "encrypted": None, "present": False}
    except Exception:  # noqa: BLE001 - S3 client errors for a missing key
        info = {"address": address, "sha256": address, "md5": None, "sha3_256": None, "size": 0, "encrypted": None, "present": False}
    lock = ctx.store.locked_until(address) if info["present"] else None
    info["object_lock_until"] = _aware(lock).isoformat() if isinstance(lock, datetime) else None
    return info


def _intake_sessions(intake_dir: Path, case_id: str) -> list[dict[str, Any]]:
    out = []
    for mf in sorted(intake_dir.glob("*/manifest.json")):
        try:
            m = json.loads(mf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if m.get("case_id") == case_id:
            files = [f for f in mf.parent.rglob("*") if f.is_file()]
            out.append({"session_id": mf.parent.name, "files": len(files), "bytes": sum(f.stat().st_size for f in files)})
    return out


def refusal(ctx: AppContext, jobs: JobStore, c: Case | None, case_id: str, now: datetime) -> str | None:
    if c is None:
        return "case not found"
    if c.status == DISPOSED:
        return "case already disposed"
    if c.legal_hold:
        return "case is on legal hold"
    if c.retention_until is None:
        return "case has no retention date"
    if _aware(c.retention_until) > now:
        return f"retention period runs until {_aware(c.retention_until).isoformat()}"
    if any(j["state"] == RUNNING for j in jobs.jobs_for_case(case_id)):
        return "case has a processing job running"
    return None


def build_plan(ctx: AppContext, jobs: JobStore, intake_dir: Path, case_ids: list[str]) -> dict[str, Any]:
    """Exactly what a disposal of ``case_ids`` would delete. Raises 409 listing every refused case."""
    now = datetime.now(timezone.utc)
    ids = list(dict.fromkeys(case_ids))
    refused = []
    with ctx.Session() as s:
        for cid in ids:
            why = refusal(ctx, jobs, s.get(Case, cid), cid, now)
            if why:
                refused.append({"case_id": cid, "reason": why})
    if refused:
        raise HTTPException(409, {"message": "disposal refused", "refused": refused})
    refs = live_references(ctx, set(ids))
    store_meta_by_case: dict[str, set[str]] = {}
    if isinstance(ctx.store, LocalStore):
        for a in ctx.store.list():
            try:
                store_meta_by_case.setdefault(ctx.store.meta(a).case_id, set()).add(a)
            except StoreError:
                continue
    cases = []
    for cid in ids:
        with ctx.Session() as s:
            c = s.get(Case, cid)
            assert c is not None  # nosec B101 - checked by refusal() above
            evs = s.query(Evidence).filter_by(case_id=cid).order_by(Evidence.id).all()
            rows = {name: s.query(model).filter_by(case_id=cid).count() for name, model in _TABLES.items()}
            ms = s.query(Membership).filter_by(case_id=cid).all()
            rows["memberships"] = sum(1 for m in ms if m.role != "lead")
            kept_members = sorted(m.user_id for m in ms if m.role == "lead")
            case_info = {"case_id": cid, "name": c.name, "retention_until": _aware(c.retention_until).isoformat() if c.retention_until else None, "ledger_id": c.ledger_id}
        evidence_objects: list[dict[str, Any]] = []
        kept: list[dict[str, Any]] = []
        seen: set[str] = set()
        for ev in evs:
            for a, role in _evidence_addresses(ev):
                if a in seen:
                    continue
                seen.add(a)
                if a in refs:
                    kept.append({"address": a, "evidence_id": ev.id, "referenced_by": sorted(refs[a])})
                    continue
                evidence_objects.append({**_object_info(ctx, a), "evidence_id": ev.id, "name": ev.name, "role": role})
        derived_objects: list[dict[str, Any]] = []
        for a in sorted((_derived_from_ledger(ctx, cid) | store_meta_by_case.get(cid, set())) - seen):
            seen.add(a)
            if a in refs:
                kept.append({"address": a, "evidence_id": None, "referenced_by": sorted(refs[a])})
                continue
            info = _object_info(ctx, a)
            if info["present"]:
                derived_objects.append(info)
        rdir = ctx.settings.reports_dir / cid
        report_files: list[dict[str, Any]] = [{"file": f.name, "size": f.stat().st_size, "sha256": _sha256_file(f)} for f in sorted(rdir.iterdir()) if f.is_file()] if rdir.is_dir() else []
        intake = _intake_sessions(intake_dir, cid)
        pending_jobs = sorted(j["job_id"] for j in jobs.jobs_for_case(cid) if j["state"] == PENDING)
        nbytes = sum(o["size"] for o in evidence_objects + derived_objects) + sum(f["size"] for f in report_files) + sum(i["bytes"] for i in intake)
        cases.append({**case_info, "evidence_objects": evidence_objects, "derived_objects": derived_objects, "kept_shared": kept,
                      "timeline_events": ctx.timeline.count(cid), "report_files": report_files, "intake_sessions": intake,
                      "pending_jobs": pending_jobs, "db_rows": rows, "memberships_kept": kept_members, "bytes": nbytes})
    return {"cases": cases}


def plan_hash(plan: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def counts(cp: dict[str, Any]) -> dict[str, Any]:
    return {"evidence_objects": len(cp["evidence_objects"]), "derived_objects": len(cp["derived_objects"]), "kept_shared": len(cp["kept_shared"]),
            "timeline_events": cp["timeline_events"], "report_files": len(cp["report_files"]), "intake_sessions": len(cp["intake_sessions"]),
            "pending_jobs": len(cp["pending_jobs"]), "db_rows": cp["db_rows"]}


def _rmtree(p: Path) -> None:
    def onexc(func, path, _exc):
        # Read-only files (WORM copies, signature docs) cannot be unlinked on Windows until the bit is cleared.
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        func(path)

    if p.exists():
        shutil.rmtree(p, onexc=onexc)


def execute_case(ctx: AppContext, jobs: JobStore, intake_dir: Path, cp: dict[str, Any], phash: str, actor: str, reason: str) -> dict[str, Any]:
    """Dispose one planned case. Returns the per-step record (also written to the ledger)."""
    cid = cp["case_id"]
    objects = [{"address": o["address"], "sha256": o["sha256"], "md5": o["md5"], "sha3_256": o["sha3_256"], "size": o["size"], "evidence_id": o.get("evidence_id"),
                "class": "evidence" if "evidence_id" in o else "derived"} for o in cp["evidence_objects"] + cp["derived_objects"]]
    # 1. declare, sign and anchor what is about to be destroyed
    intent = ctx.custody(cid, actor, "note", PURPOSE, details={
        "phase": "intent", "reason": reason, "plan_sha256": phash, "objects": objects,
        "kept_shared": [{"address": k["address"], "referenced_by": k["referenced_by"]} for k in cp["kept_shared"]],
        "report_files": cp["report_files"], "timeline_events": cp["timeline_events"], "db_rows": cp["db_rows"],
        "intake_sessions": [i["session_id"] for i in cp["intake_sessions"]], "pending_jobs": cp["pending_jobs"]})
    anchor_before = ctx.anchor(cid)
    # 2. destroy
    for jid in cp["pending_jobs"]:
        jobs.set_job(jid, FAILED, "cancelled: case disposed under retention policy")
    events_deleted = ctx.timeline.delete_case(cid)
    outcome: dict[str, list[str]] = {"deleted": [], "retained_by_object_lock": [], "delete_denied": [], "missing": []}
    for o in objects:
        outcome.setdefault(ctx.store.delete(o["address"]), []).append(o["address"])
    _rmtree(ctx.settings.reports_dir / cid)
    for i in cp["intake_sessions"]:
        _rmtree(intake_dir / i["session_id"])
    now = datetime.now(timezone.utc)
    with ctx.Session() as s:
        rows_deleted = {name: s.query(model).filter_by(case_id=cid).delete(synchronize_session=False) for name, model in _TABLES.items()}
        rows_deleted["memberships"] = s.query(Membership).filter(Membership.case_id == cid, Membership.role != "lead").delete(synchronize_session=False)
        c = s.get(Case, cid)
        assert c is not None  # nosec B101 - planned case exists
        c.status, c.disposed_at, c.disposed_by, c.disposal_reason = DISPOSED, now, actor, reason
        s.commit()
    deleted_bytes = sum(o["size"] for o in objects if o["address"] in outcome["deleted"]) + sum(f["size"] for f in cp["report_files"]) + sum(i["bytes"] for i in cp["intake_sessions"])
    # 3. record the outcome and anchor again
    done = ctx.custody(cid, actor, "note", PURPOSE, details={
        "phase": "completed", "plan_sha256": phash, "intent_entry_hash": intent["entry_hash"], "objects_deleted": outcome["deleted"],
        "objects_retained_by_object_lock": outcome["retained_by_object_lock"], "objects_delete_denied": outcome["delete_denied"], "objects_missing": outcome["missing"],
        "timeline_events_deleted": events_deleted, "db_rows_deleted": rows_deleted, "bytes_deleted": deleted_bytes})
    anchor_after = ctx.anchor(cid)
    return {"case_id": cid, "status": DISPOSED, "disposed_at": now.isoformat(), "intent_entry_hash": intent["entry_hash"], "completed_entry_hash": done["entry_hash"],
            "anchors": [anchor_before, anchor_after], "objects_deleted": outcome["deleted"], "retained_by_object_lock": outcome["retained_by_object_lock"],
            "delete_denied": outcome["delete_denied"], "objects_missing": outcome["missing"], "kept_shared": [k["address"] for k in cp["kept_shared"]], "timeline_events_deleted": events_deleted,
            "db_rows_deleted": rows_deleted, "report_files_deleted": len(cp["report_files"]), "intake_sessions_deleted": len(cp["intake_sessions"]),
            "jobs_cancelled": cp["pending_jobs"], "bytes_deleted": deleted_bytes}
