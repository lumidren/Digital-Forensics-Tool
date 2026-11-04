"""Veritas DFIR HTTP API (FastAPI).

All case-scoped routes take ``case_id`` from the path and depend on ``need(role)``; there is no
other way to reach case data. Every authenticated request is written to the hash-chained audit
log, and every read of evidence bytes appends a signed custody ``access`` or ``export`` entry.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import os
import shutil
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, File, Form, Header, HTTPException, Query as Q, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from .. import __version__
from ..analytics import execution as ex_mod
from ..analytics import lateral as lat_mod
from ..analytics import provenance as prov_mod
from ..analytics import user_activity as ua_mod
from ..analytics.ioc import Indicator, Matcher, load_indicators
from ..audit.log import verify as verify_audit
from ..pii.redact import Redactor
from ..pipeline.dag import JobStore
from ..pipeline.queue import Processor, classify
from ..reporting.model import build_model, load_template
from ..reporting.render import render_docx, render_pdf
from ..reporting.stix import stix_bundle, timeline_csv, timeline_plaso_json_line
from ..timeline.schema import Event
from ..timeline.store import Query
from . import observability as obs
from .auth import CaseAccess, Principal, case_access_factory, check_password, get_principal_factory, hash_password
from .config import Settings, load
from .context import AppContext
from .db import ROLES, Bookmark, Case, Evidence, FindingRow, Hypothesis, IocRow, Membership, Note, Report, SavedView, Task, User
from .findings import row_to_dict, run_rules, transition

log = logging.getLogger("veritas.api")


# ----------------------------------------------------------------------------- schemas
class LoginIn(BaseModel):
    username: str
    password: str


class UserIn(BaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_.@-]{2,64}$")
    display_name: str
    email: str | None = None
    password: str | None = Field(default=None, min_length=12)
    is_admin: bool = False
    can_unmask_pii: bool = False


class CaseIn(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    description: str = ""
    timezone: str | None = None


class CasePatch(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = Field(default=None, pattern="^(open|review|closed)$")
    legal_hold: bool | None = None
    retention_days: int | None = Field(default=None, ge=1, le=36500)


class MemberIn(BaseModel):
    user_id: str
    role: str = Field(pattern="^(viewer|examiner|reviewer|lead)$")


class SearchIn(BaseModel):
    text: str | None = None
    start_ns: int | None = None
    end_ns: int | None = None
    data_types: list[str] = []
    hosts: list[str] = []
    users: list[str] = []
    evidence: list[str] = []
    parsers: list[str] = []
    attr_equals: dict[str, str] = {}
    include_untimed: bool = False
    limit: int = Field(default=200, ge=1, le=5000)
    offset: int = Field(default=0, ge=0)
    descending: bool = False
    unmask: bool = False


class BookmarkIn(BaseModel):
    event_id: int
    label: str = ""
    tags: list[str] = []


class NoteIn(BaseModel):
    target_type: str = Field(pattern="^(case|event|evidence|finding|hypothesis)$")
    target_id: str
    body: str = Field(min_length=1, max_length=20000)


class HypothesisIn(BaseModel):
    title: str
    statement: str
    status: str = Field(default="open", pattern="^(open|supported|refuted)$")
    supporting_event_ids: list[int] = []
    refuting_event_ids: list[int] = []


class TaskIn(BaseModel):
    title: str
    detail: str = ""
    assignee: str | None = None
    status: str = Field(default="todo", pattern="^(todo|doing|done)$")
    due: datetime | None = None


class FindingAction(BaseModel):
    action: str = Field(pattern="^(confirm|reject|approve|return|reopen)$")
    text: str = ""


class ManualFindingIn(BaseModel):
    title: str
    description: str
    severity: str = Field(pattern="^(info|low|medium|high|critical)$")
    category: str = "manual"
    attack_techniques: list[str] = []
    event_ids: list[int] = []


class IocIn(BaseModel):
    text: str


class ViewIn(BaseModel):
    name: str
    query: dict[str, Any]


class ReportIn(BaseModel):
    format: str = Field(default="pdf", pattern="^(pdf|docx)$")
    template: str = "default"
    limitations: list[str] = []


class IntakeIn(BaseModel):
    evidence_name: str
    kind: str = "disk"
    total_size: int
    sha256: str = Field(pattern="^[0-9a-f]{64}$")
    segments: list[dict[str, Any]]  # [{"index": 0, "size": n, "sha256": h}]
    host: str | None = None
    acquired_by: str | None = None
    acquisition_entry: dict[str, Any] | None = None


# ----------------------------------------------------------------------------- app factory
def create_app(settings: Settings | None = None, start_processor: bool | None = None) -> FastAPI:
    settings = settings or load()
    ctx = AppContext(settings)
    # Cluster profile: VERITAS_JOBS_URL points at Postgres and VERITAS_INPROCESS_WORKER=0, so API pods
    # only enqueue and dedicated veritas-worker pods claim jobs (atomic leases in JobStore).
    jobs = JobStore(os.environ.get("VERITAS_JOBS_URL") or settings.data_dir / "jobs.db")
    if start_processor is None:
        start_processor = os.environ.get("VERITAS_INPROCESS_WORKER", "1") == "1"
    hub = obs.ProgressHub()
    processor = Processor(ctx, jobs, sink=hub.publish)
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        hub.loop = asyncio.get_running_loop()
        if start_processor:
            processor.start()
        yield
        processor.stop()

    app = FastAPI(title="Veritas DFIR API", version=__version__, docs_url="/api/docs", openapi_url="/api/openapi.json", lifespan=lifespan)
    app.state.ctx, app.state.jobs, app.state.processor, app.state.hub = ctx, jobs, processor, hub
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
    obs.install(app, ctx, jobs)

    get_principal = get_principal_factory(lambda: ctx.tokens, ctx.Session)
    need = case_access_factory(get_principal, ctx.Session)

    @app.middleware("http")
    async def audit_mw(request: Request, call_next):
        t0 = time.perf_counter()
        response = await call_next(request)
        p: Principal | None = getattr(request.state, "principal", None)
        if p is not None:
            parts = request.url.path.split("/")
            case_id = parts[4] if len(parts) > 4 and parts[3] == "cases" else None
            ctx.audit.append(p.user_id, f"{request.method} {request.scope.get('route').path if request.scope.get('route') else request.url.path}", case_id, request.url.path,
                             {"status": response.status_code, "ms": int((time.perf_counter() - t0) * 1000), "query": dict(request.query_params) if request.method == "GET" else {}})
        return response

    # ------------------------------------------------------------------ health / auth
    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.get("/readyz")
    def readyz():
        with ctx.Session() as s:
            s.execute(select(1))
        return {"status": "ready", "queue_depth": jobs.queue_depth()}

    @app.post("/api/v1/auth/login")
    def login(body: LoginIn):
        if not settings.local_auth:
            raise HTTPException(404, "local login disabled; use OIDC")
        with ctx.Session() as s:
            u = s.get(User, body.username)
            ok = check_password(u.password_hash if u else None, body.password)
            if not ok or not u.active:
                ctx.audit.append(body.username, "auth.login_failed", detail={})
                raise HTTPException(401, "invalid credentials")
        ctx.audit.append(u.id, "auth.login", detail={})
        return {"access_token": ctx.tokens.issue(u.id), "token_type": "bearer", "expires_in": settings.token_ttl_s}

    @app.get("/api/v1/me")
    def me(p: Principal = Depends(get_principal)):
        with ctx.Session() as s:
            ms = s.query(Membership).filter_by(user_id=p.user_id).all()
            return {**asdict(p), "cases": {m.case_id: m.role for m in ms}, "signing_key_id": ctx.vault.get_or_create(p.user_id).key_id}

    # ------------------------------------------------------------------ admin
    def admin(p: Principal = Depends(get_principal)) -> Principal:
        if not p.is_admin:
            raise HTTPException(403, "admin only")
        return p

    @app.get("/api/v1/admin/users")
    def users_list(p: Principal = Depends(admin)):
        with ctx.Session() as s:
            return [{"id": u.id, "display_name": u.display_name, "email": u.email, "is_admin": u.is_admin, "can_unmask_pii": u.can_unmask_pii, "active": u.active} for u in s.query(User).order_by(User.id)]

    @app.post("/api/v1/admin/users", status_code=201)
    def users_create(body: UserIn, p: Principal = Depends(admin)):
        with ctx.Session() as s:
            if s.get(User, body.id):
                raise HTTPException(409, "user exists")
            s.add(User(id=body.id, display_name=body.display_name, email=body.email, password_hash=hash_password(body.password) if body.password else None, is_admin=body.is_admin, can_unmask_pii=body.can_unmask_pii))
            s.commit()
        key = ctx.vault.get_or_create(body.id)
        return {"id": body.id, "signing_key_id": key.key_id}

    @app.patch("/api/v1/admin/users/{user_id}")
    def users_patch(user_id: str, body: dict = Body(...), p: Principal = Depends(admin)):
        with ctx.Session() as s:
            u = s.get(User, user_id)
            if not u:
                raise HTTPException(404, "no such user")
            for k in ("display_name", "email", "is_admin", "can_unmask_pii", "active"):
                if k in body:
                    setattr(u, k, body[k])
            if body.get("password"):
                if len(body["password"]) < 12:
                    raise HTTPException(422, "password too short")
                u.password_hash = hash_password(body["password"])
            s.commit()
        if body.get("active") is False:
            ctx.vault.revoke(user_id)
        return {"ok": True}

    @app.post("/api/v1/admin/keys/{user_id}/revoke")
    def key_revoke(user_id: str, p: Principal = Depends(admin)):
        kid = ctx.vault.revoke(user_id)
        return {"revoked_key_id": kid}

    @app.get("/api/v1/admin/audit")
    def audit_list(case_id: str | None = None, actor: str | None = None, limit: int = Q(500, le=5000), offset: int = 0, p: Principal = Depends(admin)):
        return [r.to_dict() for r in ctx.audit.rows(case_id, actor, limit, offset)]

    @app.get("/api/v1/admin/audit/verify")
    def audit_verify(p: Principal = Depends(admin)):
        ok, failures = verify_audit(ctx.audit.all_rows())
        return {"ok": ok, "failures": failures[:100]}

    @app.get("/api/v1/admin/keys")
    def keys_registry(p: Principal = Depends(get_principal)):
        return ctx.vault.registry()

    @app.post("/api/v1/admin/retention/sweep")
    def retention_sweep(p: Principal = Depends(admin)):
        """List cases past retention that are not on legal hold. Deletion is a separate, explicit action."""
        now = datetime.now(timezone.utc)
        with ctx.Session() as s:
            due = [c.id for c in s.query(Case) if c.retention_until and _aware(c.retention_until) < now and not c.legal_hold]
        return {"due_for_disposal": due}

    @app.get("/api/v1/admin/store/verify")
    def store_verify(p: Principal = Depends(admin)):
        results = [{"address": a, "ok": ok} for a, ok in ctx.store.iter_verify()] if hasattr(ctx.store, "iter_verify") else []
        return {"objects": len(results), "failed": [r for r in results if not r["ok"]]}

    # ------------------------------------------------------------------ cases
    @app.get("/api/v1/cases")
    def cases_list(p: Principal = Depends(get_principal)):
        with ctx.Session() as s:
            q = s.query(Case) if p.is_admin else s.query(Case).join(Membership).filter(Membership.user_id == p.user_id)
            out = []
            for c in q.order_by(Case.created.desc()):
                n_ev = s.query(Evidence).filter_by(case_id=c.id).count()
                n_f = s.query(FindingRow).filter_by(case_id=c.id).count()
                out.append({**_case(c), "evidence_count": n_ev, "finding_count": n_f, "event_count": ctx.timeline.count(c.id)})
            return out

    @app.post("/api/v1/cases", status_code=201)
    def cases_create(body: CaseIn, p: Principal = Depends(get_principal)):
        case_id = f"C-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"
        ledger_id = ctx.create_ledger(case_id, p.user_id)
        with ctx.Session() as s:
            s.add(Case(id=case_id, name=body.name, description=body.description, created_by=p.user_id, timezone=body.timezone, ledger_id=ledger_id,
                       retention_until=datetime.now(timezone.utc) + timedelta(days=settings.retention_days)))
            s.flush()
            s.add(Membership(case_id=case_id, user_id=p.user_id, role="lead"))
            s.commit()
            return _case(s.get(Case, case_id))

    @app.get("/api/v1/cases/{case_id}")
    def case_get(a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            c = s.get(Case, a.case_id)
            if not c:
                raise HTTPException(404, "case not found")
            members = [{"user_id": m.user_id, "role": m.role} for m in c.members]
            return {**_case(c), "members": members, "my_role": a.role, "event_count": ctx.timeline.count(c.id)}

    @app.patch("/api/v1/cases/{case_id}")
    def case_patch(body: CasePatch, a: CaseAccess = Depends(need("lead"))):
        with ctx.Session() as s:
            c = s.get(Case, a.case_id)
            for k in ("name", "description", "status", "legal_hold"):
                v = getattr(body, k)
                if v is not None:
                    setattr(c, k, v)
            if body.retention_days:
                c.retention_until = datetime.now(timezone.utc) + timedelta(days=body.retention_days)
            s.commit()
            ctx.custody(a.case_id, a.principal.user_id, "note", "case metadata changed", details={k: v for k, v in body.model_dump().items() if v is not None})
            return _case(c)

    @app.post("/api/v1/cases/{case_id}/members")
    def member_add(body: MemberIn, a: CaseAccess = Depends(need("lead"))):
        with ctx.Session() as s:
            if not s.get(User, body.user_id):
                raise HTTPException(404, "no such user")
            m = s.query(Membership).filter_by(case_id=a.case_id, user_id=body.user_id).one_or_none()
            if m:
                m.role = body.role
            else:
                s.add(Membership(case_id=a.case_id, user_id=body.user_id, role=body.role))
            s.commit()
        ctx.custody(a.case_id, a.principal.user_id, "note", f"member {body.user_id} set to {body.role}", details={"user": body.user_id, "role": body.role})
        return {"ok": True}

    @app.delete("/api/v1/cases/{case_id}/members/{user_id}")
    def member_remove(user_id: str, a: CaseAccess = Depends(need("lead"))):
        with ctx.Session() as s:
            s.query(Membership).filter_by(case_id=a.case_id, user_id=user_id).delete()
            s.commit()
        return {"ok": True}

    # ------------------------------------------------------------------ evidence
    def _register_evidence(case_id: str, actor: str, meta, name: str, kind: str, description: str, host: str | None, acquired_by: str | None,
                           acquisition: dict | None, tz_name: str | None, skew_ms: int, segments: list[dict] | None = None) -> dict:
        ev_id = f"EV-{uuid.uuid4().hex[:10].upper()}"
        if acquisition:
            ctx.custody(case_id, actor, "note", "acquisition record received from agent", evidence_id=ev_id, details={"agent_entry": acquisition})
        hashes = {"md5": meta.hashes.md5, "sha256": meta.hashes.sha256, "sha3_256": meta.hashes.sha3_256, "length": meta.hashes.length}
        if acquisition and acquisition.get("hashes") and acquisition["hashes"].get("sha256") != meta.hashes.sha256:
            raise HTTPException(409, "uploaded object hash differs from the acquisition record")
        details = {"name": name, "kind": kind, "store_address": meta.address}
        if segments:
            details["segments"] = segments
        entry = ctx.custody(case_id, actor, "ingest", f"evidence {name} stored", evidence_id=ev_id, hashes=hashes, details=details)
        with ctx.Session() as s:
            s.add(Evidence(id=ev_id, case_id=case_id, sha256=meta.hashes.sha256, md5=meta.hashes.md5, sha3_256=meta.hashes.sha3_256, size=meta.hashes.length, name=name,
                           kind=kind, description=description, host=host, acquired_by=acquired_by, tz_name=tz_name, clock_skew_ms=skew_ms, ingest_entry_hash=entry["entry_hash"], status="queued",
                           segments=segments or []))
            s.commit()
            ev = s.get(Evidence, ev_id)
            s.expunge(ev)
        head = ctx.store.open(meta.address).read(4096)
        effective = classify(head, kind, name)
        job_id = processor.enqueue(case_id, ev, effective)
        return {**_ev(ev), "job_id": job_id, "classified_as": effective}

    @app.post("/api/v1/cases/{case_id}/evidence", status_code=201)
    async def evidence_upload(file: UploadFile = File(...), kind: str = Form("file"), description: str = Form(""), host: str | None = Form(None),
                              acquired_by: str | None = Form(None), tz_name: str | None = Form(None), clock_skew_ms: int = Form(0),
                              expected_sha256: str | None = Form(None), a: CaseAccess = Depends(need("examiner"))):
        tmp = tempfile.NamedTemporaryFile(delete=False, dir=settings.data_dir)
        size = 0
        try:
            while chunk := await file.read(4 << 20):
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise HTTPException(413, "upload exceeds configured maximum")
                tmp.write(chunk)
            tmp.close()
            meta = ctx.store.put_file(a.case_id, tmp.name, file.filename)
        finally:
            Path(tmp.name).unlink(missing_ok=True)
        if expected_sha256 and expected_sha256.lower() != meta.hashes.sha256:
            raise HTTPException(409, f"hash mismatch: expected {expected_sha256}, stored {meta.hashes.sha256}")
        return _register_evidence(a.case_id, a.principal.user_id, meta, file.filename or meta.address, kind, description, host, acquired_by, None, tz_name, clock_skew_ms)

    @app.post("/api/v1/cases/{case_id}/evidence/register-path", status_code=201)
    def evidence_register_path(body: dict = Body(...), a: CaseAccess = Depends(need("examiner"))):
        """Ingest a file already present on the server (bootstrap, NAS drop folder). Admin or lead only."""
        if not (a.principal.is_admin or a.role == "lead"):
            raise HTTPException(403, "lead or admin only")
        path = Path(body["path"]).resolve()
        if not path.is_file():
            raise HTTPException(404, "file not found on server")
        meta = ctx.store.put_file(a.case_id, path, path.name)
        if body.get("expected_sha256") and body["expected_sha256"].lower() != meta.hashes.sha256:
            raise HTTPException(409, "hash mismatch")
        segments = []
        for seg in ewf_segment_set(path)[1:]:
            m = ctx.store.put_file(a.case_id, seg, seg.name)
            segments.append({"name": seg.name, "sha256": m.hashes.sha256, "md5": m.hashes.md5, "size": m.hashes.length})
        return _register_evidence(a.case_id, a.principal.user_id, meta, body.get("name") or path.name, body.get("kind", "file"), body.get("description", ""),
                                  body.get("host"), body.get("acquired_by"), body.get("acquisition_entry"), body.get("tz_name"), int(body.get("clock_skew_ms", 0)), segments)

    @app.get("/api/v1/cases/{case_id}/evidence")
    def evidence_list(a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            return [_ev(e) for e in s.query(Evidence).filter_by(case_id=a.case_id).order_by(Evidence.ingested)]

    def _get_ev(case_id: str, ev_id: str) -> Evidence:
        with ctx.Session() as s:
            e = s.get(Evidence, ev_id)
            if e is None or e.case_id != case_id:
                raise HTTPException(404, "evidence not found")
            s.expunge(e)
            return e

    @app.get("/api/v1/cases/{case_id}/evidence/{ev_id}")
    def evidence_get(ev_id: str, a: CaseAccess = Depends(need("viewer"))):
        e = _get_ev(a.case_id, ev_id)
        return {**_ev(e), "jobs": [j for j in jobs.jobs_for_case(a.case_id) if j["evidence_sha256"] == e.sha256]}

    @app.get("/api/v1/cases/{case_id}/evidence/{ev_id}/bytes")
    def evidence_bytes(ev_id: str, offset: int = Q(0, ge=0), length: int = Q(4096, ge=1, le=1 << 20), a: CaseAccess = Depends(need("examiner"))):
        """Hex-viewer read. Every call is a recorded custody access."""
        e = _get_ev(a.case_id, ev_id)
        ctx.custody(a.case_id, a.principal.user_id, "access", "hex view", evidence_id=e.id, details={"offset": offset, "length": length})
        with ctx.store.open(e.sha256) as fh:
            _skip(fh, offset)
            data = fh.read(length)
        return {"offset": offset, "length": len(data), "hex": data.hex(), "size": e.size}

    @app.get("/api/v1/cases/{case_id}/evidence/{ev_id}/download")
    def evidence_download(ev_id: str, reason: str = Q(..., min_length=5), a: CaseAccess = Depends(need("lead"))):
        e = _get_ev(a.case_id, ev_id)
        ctx.custody(a.case_id, a.principal.user_id, "export", f"evidence exported: {reason}", evidence_id=e.id, hashes={"md5": e.md5, "sha256": e.sha256, "sha3_256": e.sha3_256, "length": e.size})
        fh = ctx.store.open(e.sha256)
        return StreamingResponse(iter(lambda: fh.read(1 << 20), b""), media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{e.id}.bin"', "X-Evidence-SHA256": e.sha256})

    @app.post("/api/v1/cases/{case_id}/evidence/{ev_id}/verify")
    def evidence_verify(ev_id: str, a: CaseAccess = Depends(need("examiner"))):
        e = _get_ev(a.case_id, ev_id)
        ok = ctx.store.verify(e.sha256)
        ctx.custody(a.case_id, a.principal.user_id, "access", "integrity re-verification", evidence_id=e.id, details={"result": "match" if ok else "MISMATCH"})
        return {"ok": ok, "sha256": e.sha256}

    @app.post("/api/v1/cases/{case_id}/evidence/{ev_id}/reprocess")
    def evidence_reprocess(ev_id: str, kind: str | None = None, a: CaseAccess = Depends(need("examiner"))):
        e = _get_ev(a.case_id, ev_id)
        head = ctx.store.open(e.sha256).read(4096)
        return {"job_id": processor.enqueue(a.case_id, e, kind or classify(head, e.kind, e.name))}

    # ------------------------------------------------------------------ agent intake (resumable)
    intake_dir = settings.data_dir / "intake"
    intake_dir.mkdir(exist_ok=True)

    @app.post("/api/v1/intake/sessions", status_code=201)
    def intake_create(body: IntakeIn, case_id: str = Q(...), a: CaseAccess = Depends(need("examiner"))):
        sid = uuid.uuid4().hex
        d = intake_dir / sid
        d.mkdir()
        (d / "manifest.json").write_text(json.dumps({**body.model_dump(), "case_id": case_id, "user": a.principal.user_id}), encoding="utf-8")
        return {"session_id": sid}

    def _intake(sid: str, p: Principal) -> tuple[Path, dict]:
        if not sid.isalnum():
            raise HTTPException(400, "bad session id")
        d = intake_dir / sid
        if not (d / "manifest.json").exists():
            raise HTTPException(404, "no such session")
        m = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        if m["user"] != p.user_id and not p.is_admin:
            raise HTTPException(404, "no such session")
        return d, m

    @app.get("/api/v1/intake/sessions/{sid}")
    def intake_status(sid: str, p: Principal = Depends(get_principal)):
        d, m = _intake(sid, p)
        present = sorted(int(f.stem) for f in d.glob("*.seg"))
        return {"session_id": sid, "present": present, "total": len(m["segments"])}

    @app.put("/api/v1/intake/sessions/{sid}/segments/{n}")
    async def intake_segment(sid: str, n: int, request: Request, x_segment_sha256: str = Header(...), p: Principal = Depends(get_principal)):
        d, m = _intake(sid, p)
        segs = {s["index"]: s for s in m["segments"]}
        if n not in segs or segs[n]["sha256"] != x_segment_sha256.lower():
            raise HTTPException(409, "segment not in manifest or hash differs from manifest")
        h = hashlib.sha256()
        tmp = d / f"{n}.part"
        with open(tmp, "wb") as fh:
            async for chunk in request.stream():
                h.update(chunk)
                fh.write(chunk)
        if h.hexdigest() != x_segment_sha256.lower():
            tmp.unlink(missing_ok=True)
            raise HTTPException(422, "segment hash mismatch; resend")
        tmp.replace(d / f"{n}.seg")
        return {"ok": True}

    @app.post("/api/v1/intake/sessions/{sid}/complete", status_code=201)
    def intake_complete(sid: str, p: Principal = Depends(get_principal)):
        d, m = _intake(sid, p)
        missing = [s["index"] for s in m["segments"] if not (d / f"{s['index']}.seg").exists()]
        if missing:
            raise HTTPException(409, f"missing segments {missing[:20]}")
        joined = d / "joined.bin"
        with open(joined, "wb") as out:
            for s in sorted(m["segments"], key=lambda s: s["index"]):
                with open(d / f"{s['index']}.seg", "rb") as fh:
                    shutil.copyfileobj(fh, out, 4 << 20)
        meta = ctx.store.put_file(m["case_id"], joined, m["evidence_name"])
        if meta.hashes.sha256 != m["sha256"]:
            raise HTTPException(409, "assembled evidence hash differs from the manifest")
        res = _register_evidence(m["case_id"], p.user_id, meta, m["evidence_name"], m["kind"], "uploaded by acquisition agent", m.get("host"), m.get("acquired_by"), m.get("acquisition_entry"), None, 0)
        shutil.rmtree(d, ignore_errors=True)
        return res

    # ------------------------------------------------------------------ jobs and progress
    @app.get("/api/v1/cases/{case_id}/jobs")
    def jobs_list(a: CaseAccess = Depends(need("viewer"))):
        return jobs.jobs_for_case(a.case_id)

    @app.websocket("/api/v1/cases/{case_id}/ws")
    async def ws(websocket: WebSocket, case_id: str):
        # Prefer the Sec-WebSocket-Protocol header ("veritas.bearer.<token>") so the token never
        # appears in a URL; the query parameter remains for older clients and is scrubbed from logs.
        protocols = [p.strip() for p in websocket.headers.get("sec-websocket-protocol", "").split(",") if p.strip()]
        header_token = next((p[len("veritas.bearer."):] for p in protocols if p.startswith("veritas.bearer.")), None)
        token = header_token or websocket.query_params.get("access_token")
        try:
            claims = ctx.tokens.verify(token or "")
        except HTTPException:
            await websocket.close(code=4401)
            return
        with ctx.Session() as s:
            u = s.get(User, claims["sub"])
            m = s.query(Membership).filter_by(case_id=case_id, user_id=claims["sub"]).one_or_none()
        if u is None or (m is None and not u.is_admin):
            await websocket.close(code=4404)
            return
        await websocket.accept(subprotocol="veritas.bearer" if header_token else None)
        q = hub.subscribe()
        try:
            while True:
                msg = await q.get()
                job = jobs.job(msg.get("job_id", "")) or {}
                if job.get("case_id") == case_id:
                    await websocket.send_json(msg)
        except WebSocketDisconnect:
            pass
        finally:
            hub.unsubscribe(q)

    # ------------------------------------------------------------------ timeline
    def _redactor(case_id: str) -> Redactor:
        return Redactor(ctx.keyring.case_key(case_id))

    def _maybe_redact(a: CaseAccess, events: list[Event], unmask: bool) -> list[Event]:
        if unmask:
            if not a.principal.can_unmask_pii:
                raise HTTPException(403, "PII unmasking requires the pii.unmask permission")
            ctx.audit.append(a.principal.user_id, "pii.unmask", a.case_id, None, {"events": len(events)})
            return events
        if not settings.redact_by_default:
            return events
        r = _redactor(a.case_id)
        return [r.redact_event(e) for e in events]

    def _q(body: SearchIn) -> Query:
        return Query(**body.model_dump(exclude={"unmask"}))

    @app.post("/api/v1/cases/{case_id}/timeline/search")
    def timeline_search(body: SearchIn, a: CaseAccess = Depends(need("viewer"))):
        t0 = time.perf_counter()
        res = ctx.timeline.search(a.case_id, _q(body))
        obs.SEARCH_LATENCY.observe(time.perf_counter() - t0)
        evs = _maybe_redact(a, [se.event for se in res.events], body.unmask)
        return {"total": res.total, "events": [{"id": se.id, **e.to_dict()} for se, e in zip(res.events, evs)], "ms": int((time.perf_counter() - t0) * 1000)}

    @app.post("/api/v1/cases/{case_id}/timeline/histogram")
    def timeline_histogram(body: SearchIn, bucket: str = "auto", a: CaseAccess = Depends(need("viewer"))):
        q = _q(body)
        if bucket == "auto":
            rng = ctx.timeline.search(a.case_id, Query(**{**body.model_dump(exclude={"unmask"}), "limit": 1}))
            first = ctx.timeline.search(a.case_id, Query(**{**body.model_dump(exclude={"unmask"}), "limit": 1, "descending": False}))
            last = ctx.timeline.search(a.case_id, Query(**{**body.model_dump(exclude={"unmask"}), "limit": 1, "descending": True}))
            if not first.events or not rng.total:
                return {"bucket_ns": 0, "buckets": []}
            span = max(1, (last.events[0].event.timestamp or 0) - (first.events[0].event.timestamp or 0))
            steps = [10**9, 60 * 10**9, 3600 * 10**9, 86400 * 10**9, 7 * 86400 * 10**9, 30 * 86400 * 10**9, 365 * 86400 * 10**9]
            bucket_ns = next((s for s in steps if span / s <= 400), steps[-1])
        else:
            bucket_ns = int(bucket)
        return {"bucket_ns": bucket_ns, "buckets": [asdict(b) for b in ctx.timeline.histogram(a.case_id, q, bucket_ns)]}

    @app.post("/api/v1/cases/{case_id}/timeline/facets/{column}")
    def timeline_facets(column: str, body: SearchIn, a: CaseAccess = Depends(need("viewer"))):
        try:
            return [{"value": v, "count": n} for v, n in ctx.timeline.facets(a.case_id, _q(body), column)]
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/v1/cases/{case_id}/events/{event_id}")
    def event_get(event_id: int, unmask: bool = False, a: CaseAccess = Depends(need("viewer"))):
        se = ctx.timeline.get(a.case_id, event_id)
        if se is None:
            raise HTTPException(404, "event not found")
        e = _maybe_redact(a, [se.event], unmask)[0]
        return {"id": se.id, **e.to_dict()}

    @app.get("/api/v1/cases/{case_id}/timeline/export")
    def timeline_export(fmt: str = Q("jsonl", pattern="^(jsonl|csv|plaso)$"), unmask: bool = False, a: CaseAccess = Depends(need("examiner"))):
        events = _maybe_redact(a, [se.event for se in ctx.timeline.iter_events(a.case_id)], unmask)
        if fmt == "csv":
            body, mt = timeline_csv(events), "text/csv"
        elif fmt == "plaso":
            body, mt = "\n".join(timeline_plaso_json_line(e) for e in events) + "\n", "application/x-ndjson"
        else:
            body, mt = "\n".join(e.to_json() for e in events) + "\n", "application/x-ndjson"
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        ctx.custody(a.case_id, a.principal.user_id, "export", f"timeline exported ({fmt})", details={"events": len(events), "sha256": digest, "redacted": not unmask})
        return Response(body, media_type=mt, headers={"Content-Disposition": f'attachment; filename="{a.case_id}-timeline.{ "csv" if fmt == "csv" else "jsonl"}"', "X-Content-SHA256": digest})

    @app.get("/api/v1/cases/{case_id}/views")
    def views_list(a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            return [{"id": v.id, "name": v.name, "query": v.query, "user_id": v.user_id} for v in s.query(SavedView).filter_by(case_id=a.case_id).order_by(SavedView.name)]

    @app.post("/api/v1/cases/{case_id}/views", status_code=201)
    def views_create(body: ViewIn, a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            v = SavedView(case_id=a.case_id, user_id=a.principal.user_id, name=body.name, query=body.query)
            s.add(v)
            s.commit()
            return {"id": v.id}

    # ------------------------------------------------------------------ collaboration
    @app.get("/api/v1/cases/{case_id}/bookmarks")
    def bookmarks_list(a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            return [{"id": b.id, "event_id": b.event_id, "label": b.label, "tags": b.tags, "user_id": b.user_id, "created": b.created.isoformat()} for b in s.query(Bookmark).filter_by(case_id=a.case_id).order_by(Bookmark.id)]

    @app.post("/api/v1/cases/{case_id}/bookmarks", status_code=201)
    def bookmarks_create(body: BookmarkIn, a: CaseAccess = Depends(need("examiner"))):
        if ctx.timeline.get(a.case_id, body.event_id) is None:
            raise HTTPException(404, "event not found")
        with ctx.Session() as s:
            b = Bookmark(case_id=a.case_id, event_id=body.event_id, user_id=a.principal.user_id, label=body.label, tags=sorted(set(body.tags)))
            s.add(b)
            s.commit()
            return {"id": b.id}

    @app.delete("/api/v1/cases/{case_id}/bookmarks/{bid}")
    def bookmarks_delete(bid: int, a: CaseAccess = Depends(need("examiner"))):
        with ctx.Session() as s:
            s.query(Bookmark).filter_by(case_id=a.case_id, id=bid).delete()
            s.commit()
        return {"ok": True}

    @app.get("/api/v1/cases/{case_id}/notes")
    def notes_list(target_type: str | None = None, target_id: str | None = None, a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            q = s.query(Note).filter_by(case_id=a.case_id)
            if target_type:
                q = q.filter_by(target_type=target_type)
            if target_id:
                q = q.filter_by(target_id=target_id)
            return [{"id": n.id, "user_id": n.user_id, "target_type": n.target_type, "target_id": n.target_id, "body": n.body, "created": n.created.isoformat()} for n in q.order_by(Note.id)]

    @app.post("/api/v1/cases/{case_id}/notes", status_code=201)
    def notes_create(body: NoteIn, a: CaseAccess = Depends(need("examiner"))):
        with ctx.Session() as s:
            n = Note(case_id=a.case_id, user_id=a.principal.user_id, **body.model_dump())
            s.add(n)
            s.commit()
            return {"id": n.id}

    @app.get("/api/v1/cases/{case_id}/hypotheses")
    def hyp_list(a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            return [_row(h) for h in s.query(Hypothesis).filter_by(case_id=a.case_id).order_by(Hypothesis.id)]

    @app.post("/api/v1/cases/{case_id}/hypotheses", status_code=201)
    def hyp_create(body: HypothesisIn, a: CaseAccess = Depends(need("examiner"))):
        with ctx.Session() as s:
            h = Hypothesis(case_id=a.case_id, user_id=a.principal.user_id, **body.model_dump())
            s.add(h)
            s.commit()
            return {"id": h.id}

    @app.put("/api/v1/cases/{case_id}/hypotheses/{hid}")
    def hyp_update(hid: int, body: HypothesisIn, a: CaseAccess = Depends(need("examiner"))):
        with ctx.Session() as s:
            h = s.get(Hypothesis, hid)
            if not h or h.case_id != a.case_id:
                raise HTTPException(404, "not found")
            for k, v in body.model_dump().items():
                setattr(h, k, v)
            s.commit()
            return _row(h)

    @app.get("/api/v1/cases/{case_id}/tasks")
    def tasks_list(a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            return [_row(t) for t in s.query(Task).filter_by(case_id=a.case_id).order_by(Task.id)]

    @app.post("/api/v1/cases/{case_id}/tasks", status_code=201)
    def tasks_create(body: TaskIn, a: CaseAccess = Depends(need("examiner"))):
        with ctx.Session() as s:
            if body.assignee and not s.query(Membership).filter_by(case_id=a.case_id, user_id=body.assignee).one_or_none():
                raise HTTPException(422, "assignee is not a case member")
            t = Task(case_id=a.case_id, created_by=a.principal.user_id, **body.model_dump())
            s.add(t)
            s.commit()
            return {"id": t.id}

    @app.put("/api/v1/cases/{case_id}/tasks/{tid}")
    def tasks_update(tid: int, body: TaskIn, a: CaseAccess = Depends(need("examiner"))):
        with ctx.Session() as s:
            t = s.get(Task, tid)
            if not t or t.case_id != a.case_id:
                raise HTTPException(404, "not found")
            for k, v in body.model_dump().items():
                setattr(t, k, v)
            s.commit()
            return _row(t)

    @app.get("/api/v1/cases/{case_id}/activity")
    def case_activity(limit: int = Q(200, le=2000), a: CaseAccess = Depends(need("lead"))):
        """Who looked at what: the audit trail for this case."""
        return [r.to_dict() for r in ctx.audit.rows(case_id=a.case_id, limit=limit)]

    # ------------------------------------------------------------------ analytics and findings
    @app.post("/api/v1/cases/{case_id}/findings/run")
    def findings_run(a: CaseAccess = Depends(need("examiner"))):
        return {"proposed": run_rules(ctx, a.case_id)}

    @app.get("/api/v1/cases/{case_id}/findings")
    def findings_list(state: str | None = None, a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            q = s.query(FindingRow).filter_by(case_id=a.case_id)
            if state:
                q = q.filter_by(state=state)
            rows = sorted(q.all(), key=lambda r: (["critical", "high", "medium", "low", "info"].index(r.severity), -r.confidence, r.title))
            return [row_to_dict(r) for r in rows]

    @app.post("/api/v1/cases/{case_id}/findings", status_code=201)
    def findings_manual(body: ManualFindingIn, a: CaseAccess = Depends(need("examiner"))):
        from ..analytics.findings import Finding

        f = Finding("manual", body.title, body.description, body.severity, 1.0, body.category, body.attack_techniques, body.event_ids, details={"author": a.principal.user_id})
        with ctx.Session() as s:
            s.add(FindingRow(id=f.finding_id, case_id=a.case_id, rule="manual", title=f.title, description=f.description, severity=f.severity, confidence=1.0, category=f.category,
                             attack_techniques=f.attack_techniques, event_ids=f.event_ids, evidence_sha256=[], details=f.details, state="proposed", origin="manual"))
            s.commit()
        return {"id": f.finding_id}

    @app.post("/api/v1/cases/{case_id}/findings/{fid}/action")
    def findings_action(fid: str, body: FindingAction, a: CaseAccess = Depends(need("examiner"))):
        with ctx.Session() as s:
            r = s.get(FindingRow, fid)
            if not r or r.case_id != a.case_id:
                raise HTTPException(404, "finding not found")
            transition(r, body.action, a.principal.user_id, a.at_least, body.text)
            s.commit()
            out = row_to_dict(r)
        ctx.custody(a.case_id, a.principal.user_id, "note", f"finding {fid} {body.action}", details={"finding_id": fid, "action": body.action, "state": out["state"]})
        return out

    @app.get("/api/v1/cases/{case_id}/analytics/execution")
    def analytics_execution(a: CaseAccess = Depends(need("viewer"))):
        rows = ex_mod.correlate(ctx.timeline.iter_events(a.case_id))
        return [r.to_dict() for _, r in sorted(rows.items())]

    @app.get("/api/v1/cases/{case_id}/analytics/lateral")
    def analytics_lateral(a: CaseAccess = Depends(need("viewer"))):
        edges = lat_mod.build_graph(ctx.timeline.iter_events(a.case_id))
        nodes = sorted({e.src for e in edges} | {e.dst for e in edges})
        return {"nodes": [{"id": n} for n in nodes], "edges": [e.to_dict() for e in edges]}

    @app.get("/api/v1/cases/{case_id}/analytics/provenance")
    def analytics_provenance(path: str | None = None, a: CaseAccess = Depends(need("viewer"))):
        nodes = prov_mod.build(ctx.timeline.iter_events(a.case_id))
        if path:
            n = nodes.get(prov_mod.norm(path))
            return n.to_dict() if n else {}
        return [n.to_dict() for _, n in sorted(nodes.items()) if n.origin_kind or len(n.events) > 1][:2000]

    @app.get("/api/v1/cases/{case_id}/analytics/users")
    def analytics_users(a: CaseAccess = Depends(need("viewer"))):
        return ua_mod.reconstruct(ctx.timeline.iter_events(a.case_id))

    # ------------------------------------------------------------------ IOCs
    @app.get("/api/v1/cases/{case_id}/iocs")
    def iocs_list(a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            return [{"id": i.id, "ioc_id": i.ioc_id, "ioc_type": i.ioc_type, "value": i.value, "source": i.source, "tags": i.tags, "hits": i.hits} for i in s.query(IocRow).filter_by(case_id=a.case_id).order_by(IocRow.ioc_type, IocRow.value)]

    @app.post("/api/v1/cases/{case_id}/iocs", status_code=201)
    def iocs_import(body: IocIn, a: CaseAccess = Depends(need("examiner"))):
        try:
            inds = load_indicators(body.text)
        except (ValueError, KeyError) as exc:
            raise HTTPException(422, f"invalid indicator: {exc}") from exc
        added = 0
        with ctx.Session() as s:
            for i in inds:
                if not s.query(IocRow).filter_by(case_id=a.case_id, ioc_id=i.ioc_id).one_or_none():
                    s.add(IocRow(case_id=a.case_id, ioc_id=i.ioc_id, ioc_type=i.ioc_type, value=i.value, source=i.source, tags=i.tags))
                    added += 1
            s.commit()
        return {"added": added, "total": len(inds)}

    @app.delete("/api/v1/cases/{case_id}/iocs/{iid}")
    def iocs_delete(iid: int, a: CaseAccess = Depends(need("examiner"))):
        with ctx.Session() as s:
            s.query(IocRow).filter_by(case_id=a.case_id, id=iid).delete()
            s.commit()
        return {"ok": True}

    @app.post("/api/v1/cases/{case_id}/iocs/sweep")
    def iocs_sweep(a: CaseAccess = Depends(need("examiner"))):
        with ctx.Session() as s:
            rows = s.query(IocRow).filter_by(case_id=a.case_id).all()
            inds = [Indicator(r.ioc_type, r.value, r.source, r.tags) for r in rows]
        hits = list(Matcher(inds).sweep(ctx.timeline.iter_events(a.case_id)))
        counts: dict[str, int] = {}
        for h in hits:
            counts[h.ioc_id] = counts.get(h.ioc_id, 0) + 1
        with ctx.Session() as s:
            for r in s.query(IocRow).filter_by(case_id=a.case_id):
                r.hits = counts.get(r.ioc_id, 0)
            s.commit()
        return {"hits": [h.to_dict() for h in hits[:5000]], "total": len(hits), "by_ioc": counts}

    @app.get("/api/v1/cases/{case_id}/iocs/stix")
    def iocs_stix(a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            c = s.get(Case, a.case_id)
            rows = [{"ioc_type": r.ioc_type, "value": r.value, "source": r.source, "tags": r.tags, "hits": r.hits, "created": _aware(r.created)} for r in s.query(IocRow).filter_by(case_id=a.case_id)]
        return JSONResponse(stix_bundle(a.case_id, c.name, rows, a.principal.user_id), media_type="application/stix+json;version=2.1")

    # ------------------------------------------------------------------ custody
    @app.get("/api/v1/cases/{case_id}/custody")
    def custody_entries(evidence_id: str | None = None, kind: str | None = None, limit: int = Q(1000, le=100000), offset: int = 0, a: CaseAccess = Depends(need("viewer"))):
        entries = ctx.ledger(a.case_id).entries()
        if evidence_id:
            entries = [e for e in entries if e.get("evidence_id") == evidence_id]
        if kind:
            entries = [e for e in entries if e["kind"] == kind]
        return {"total": len(entries), "entries": entries[offset:offset + limit]}

    @app.get("/api/v1/cases/{case_id}/custody/verify")
    def custody_verify(a: CaseAccess = Depends(need("viewer"))):
        ok, failures = ctx.verify_custody(a.case_id)
        head = ctx.ledger(a.case_id).head()
        return {"verdict": "PASS" if ok else "FAIL", "failures": failures[:200], "entries": head["seq"] + 1 if head else 0, "head_hash": head["entry_hash"] if head else None}

    @app.get("/api/v1/cases/{case_id}/custody/export")
    def custody_export(a: CaseAccess = Depends(need("examiner"))):
        export = ctx.custody_export(a.case_id, a.principal.user_id)
        body = json.dumps(export, ensure_ascii=False, indent=2)
        return Response(body, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{a.case_id}-custody.json"'})

    @app.post("/api/v1/cases/{case_id}/custody/anchor")
    def custody_anchor(a: CaseAccess = Depends(need("lead"))):
        try:
            return ctx.anchor(a.case_id)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    # ------------------------------------------------------------------ reports
    @app.post("/api/v1/cases/{case_id}/reports", status_code=201)
    def reports_build(body: ReportIn, a: CaseAccess = Depends(need("examiner"))):
        model = _report_model(a, body)
        data = render_pdf(model) if body.format == "pdf" else render_docx(model)
        digest = hashlib.sha256(data).hexdigest()
        key = ctx.vault.get_or_create(a.principal.user_id)
        sig = key.sign(bytes.fromhex(digest)).hex()
        out_dir = settings.reports_dir / a.case_id
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{digest}.{body.format}"
        if not path.exists():
            path.write_bytes(data)
        signature_doc = {"report_sha256": digest, "state_hash": model.state_hash(), "signer": a.principal.user_id, "signer_key_id": key.key_id, "signer_public_key": key.public_key_hex, "signature_ed25519": sig, "format": body.format, "case_id": a.case_id}
        (out_dir / f"{digest}.sig.json").write_text(json.dumps(signature_doc, indent=2, sort_keys=True), encoding="utf-8")
        entry = ctx.custody(a.case_id, a.principal.user_id, "transform", f"report generated ({body.format})", hashes={"md5": hashlib.md5(data, usedforsecurity=False).hexdigest(), "sha256": digest, "sha3_256": hashlib.sha3_256(data).hexdigest(), "length": len(data)},
                            details={"state_hash": model.state_hash(), "template": body.template, "signature": sig})
        rid = f"R-{digest[:12]}"
        with ctx.Session() as s:
            if not s.get(Report, rid):
                s.add(Report(id=rid, case_id=a.case_id, created_by=a.principal.user_id, format=body.format, sha256=digest, state_hash=model.state_hash(), signature=sig, signer_key_id=key.key_id, ledger_entry_hash=entry["entry_hash"], path=str(path)))
                s.commit()
        return {"id": rid, **signature_doc, "ledger_entry_hash": entry["entry_hash"], "size": len(data)}

    def _report_model(a: CaseAccess, body: ReportIn):
        with ctx.Session() as s:
            c = s.get(Case, a.case_id)
            ev = [_ev(e) for e in s.query(Evidence).filter_by(case_id=a.case_id)]
            approved = [row_to_dict(r) for r in s.query(FindingRow).filter_by(case_id=a.case_id, state="approved")]
            u = s.get(User, a.principal.user_id)
        ids = sorted({i for f in approved for i in f["event_ids"]})
        events_by_id = {}
        for i in ids:
            se = ctx.timeline.get(a.case_id, i)
            if se:
                events_by_id[i] = se.event.to_dict()
        try:
            tpl = load_template(settings.report_template_dir, body.template)
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from exc
        return build_model(
            template=tpl, case={"id": c.id, "name": c.name, "description": c.description}, examiner={"id": u.id, "display_name": u.display_name},
            reviewers=[f["approved_by"] for f in approved if f["approved_by"]], evidence=ev, ledger_entries=ctx.ledger(a.case_id).entries(),
            findings=approved, events_by_id=events_by_id, tools=obs.tool_inventory(), parity=obs.parity_summary(), limitations_extra=body.limitations,
        )

    @app.get("/api/v1/cases/{case_id}/reports")
    def reports_list(a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            return [{"id": r.id, "format": r.format, "sha256": r.sha256, "state_hash": r.state_hash, "created_by": r.created_by, "created": r.created.isoformat(), "ledger_entry_hash": r.ledger_entry_hash, "signer_key_id": r.signer_key_id, "signature": r.signature} for r in s.query(Report).filter_by(case_id=a.case_id).order_by(Report.created)]

    @app.get("/api/v1/cases/{case_id}/reports/{rid}/download")
    def reports_download(rid: str, part: str = Q("document", pattern="^(document|signature)$"), a: CaseAccess = Depends(need("viewer"))):
        with ctx.Session() as s:
            r = s.get(Report, rid)
            if not r or r.case_id != a.case_id:
                raise HTTPException(404, "report not found")
        p = Path(r.path)
        if part == "signature":
            return Response(p.with_name(f"{r.sha256}.sig.json").read_bytes(), media_type="application/json")
        data = p.read_bytes()
        if hashlib.sha256(data).hexdigest() != r.sha256:
            raise HTTPException(500, "stored report no longer matches its hash")
        mt = "application/pdf" if r.format == "pdf" else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        return Response(data, media_type=mt, headers={"Content-Disposition": f'attachment; filename="{a.case_id}-{r.id}.{r.format}"', "X-Report-SHA256": r.sha256})

    # ------------------------------------------------------------------ misc
    @app.get("/api/v1/meta/attack")
    def meta_attack(p: Principal = Depends(get_principal)):
        from ..analytics.attack import TECHNIQUES

        return TECHNIQUES

    @app.get("/api/v1/meta/roles")
    def meta_roles():
        return {"case_roles": list(ROLES)}

    return app


# ----------------------------------------------------------------------------- helpers
def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _case(c: Case) -> dict[str, Any]:
    return {"id": c.id, "name": c.name, "description": c.description, "status": c.status, "created_by": c.created_by, "created": _aware(c.created).isoformat(),
            "timezone": c.timezone, "legal_hold": c.legal_hold, "retention_until": _aware(c.retention_until).isoformat() if c.retention_until else None, "ledger_id": c.ledger_id}


def ewf_segment_set(first: Path) -> list[Path]:
    """``x.E01`` plus its continuation segments ``x.E02`` ... ``x.E99``, ``x.EAA`` ... in EWF order."""
    if first.suffix.upper() != ".E01":
        return [first]
    out = [first]
    names = {p.name.upper(): p for p in first.parent.iterdir() if p.is_file()}
    stem = first.name[: -len(first.suffix)].upper()
    nums = [f"E{i:02d}" for i in range(2, 100)]
    letters = [f"E{a}{b}" for a in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    for ext in nums + letters:
        p = names.get(f"{stem}.{ext}")
        if p is None:
            break
        out.append(p)
    return out


def _ev(e: Evidence) -> dict[str, Any]:
    return {"id": e.id, "case_id": e.case_id, "sha256": e.sha256, "md5": e.md5, "sha3_256": e.sha3_256, "size": e.size, "name": e.name, "kind": e.kind, "description": e.description,
            "host": e.host, "acquired_by": e.acquired_by, "tz_name": e.tz_name, "clock_skew_ms": e.clock_skew_ms, "ingest_entry_hash": e.ingest_entry_hash,
            "ingested": _aware(e.ingested).isoformat(), "status": e.status, "segments": e.segments or []}


def _row(o) -> dict[str, Any]:
    d = {}
    for col in o.__table__.columns:
        v = getattr(o, col.name)
        d[col.name] = _aware(v).isoformat() if isinstance(v, datetime) else v
    return d


def _skip(fh, n: int) -> None:
    try:
        fh.seek(n)
    except (OSError, io.UnsupportedOperation):
        while n > 0:
            chunk = fh.read(min(n, 1 << 20))
            if not chunk:
                break
            n -= len(chunk)


def run() -> None:
    import uvicorn

    # JSON logs through the scrubbing formatter, including uvicorn's access log (query strings may
    # carry access_token for legacy WebSocket clients).
    obs.configure_logging(os.environ.get("VERITAS_LOG_LEVEL", "INFO"))
    uvicorn.run("veritas.api.main:create_app", factory=True, host=os.environ.get("VERITAS_HOST", "127.0.0.1"), port=int(os.environ.get("VERITAS_PORT", "8000")), log_config=None)
