"""Findings workflow: rules propose, examiners confirm or reject, an independent reviewer approves.

State machine::

    proposed --(examiner: confirm + rationale)--> confirmed --(reviewer != confirmer: approve)--> approved
    proposed --(examiner: reject + rationale)--> rejected
    confirmed --(reviewer: return)--> proposed

Only approved findings are included in reports. THREAT:T5.1
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from ..analytics.findings import Finding, FindingsEngine
from .db import FindingRow

ALLOWED = {
    ("proposed", "confirm"): "confirmed",
    ("proposed", "reject"): "rejected",
    ("rejected", "reopen"): "proposed",
    ("confirmed", "approve"): "approved",
    ("confirmed", "return"): "proposed",
}
ROLE_FOR_ACTION = {"confirm": "examiner", "reject": "examiner", "reopen": "examiner", "approve": "reviewer", "return": "reviewer"}


def row_to_dict(r: FindingRow) -> dict[str, Any]:
    return {
        "id": r.id, "case_id": r.case_id, "rule": r.rule, "title": r.title, "description": r.description, "severity": r.severity,
        "confidence": r.confidence, "category": r.category, "attack_techniques": r.attack_techniques, "event_ids": r.event_ids,
        "evidence_sha256": r.evidence_sha256, "details": r.details, "first_ns": r.first_ns, "last_ns": r.last_ns, "state": r.state,
        "origin": r.origin, "confirmed_by": r.confirmed_by, "confirmed_at": r.confirmed_at.isoformat() if r.confirmed_at else None,
        "approved_by": r.approved_by, "approved_at": r.approved_at.isoformat() if r.approved_at else None,
        "examiner_rationale": r.examiner_rationale, "reviewer_comment": r.reviewer_comment,
    }


def upsert_proposal(s, case_id: str, f: Finding) -> bool:
    existing = s.get(FindingRow, f.finding_id)
    if existing is not None:
        # Never touch a finding a human has acted on; refresh only untouched proposals.
        if existing.state == "proposed" and existing.confirmed_by is None:
            existing.event_ids, existing.details, existing.confidence = f.event_ids, f.details, f.confidence
        return False
    s.add(FindingRow(
        id=f.finding_id, case_id=case_id, rule=f.rule, title=f.title, description=f.description, severity=f.severity, confidence=f.confidence,
        category=f.category, attack_techniques=f.attack_techniques, event_ids=f.event_ids, evidence_sha256=f.evidence_sha256,
        details=f.details, first_ns=f.first_ns, last_ns=f.last_ns, state="proposed", origin="rule",
    ))
    return True


def run_rules(ctx, case_id: str) -> int:
    findings = FindingsEngine().run(ctx.timeline.iter_events(case_id))
    created = 0
    with ctx.Session() as s:
        for f in findings:
            created += upsert_proposal(s, case_id, f)
        s.commit()
    return created


def transition(row: FindingRow, action: str, actor: str, actor_role_ok, text: str) -> None:
    key = (row.state, action)
    if key not in ALLOWED:
        raise HTTPException(409, f"cannot {action} a finding in state {row.state}")
    if not actor_role_ok(ROLE_FOR_ACTION[action]):
        raise HTTPException(403, f"{action} requires role {ROLE_FOR_ACTION[action]}")
    if action in ("confirm", "reject") and len(text.strip()) < 10:
        raise HTTPException(422, "a rationale of at least 10 characters is required")
    if action == "approve" and row.confirmed_by == actor:
        raise HTTPException(403, "a finding must be approved by a reviewer other than the examiner who confirmed it")
    now = datetime.now(timezone.utc)
    row.state = ALLOWED[key]
    if action in ("confirm", "reject"):
        row.confirmed_by, row.confirmed_at, row.examiner_rationale = actor, now, text.strip()
    elif action == "approve":
        row.approved_by, row.approved_at, row.reviewer_comment = actor, now, text.strip()
    elif action == "return":
        row.reviewer_comment = text.strip()
        row.confirmed_by = row.confirmed_at = None
    elif action == "reopen":
        row.confirmed_by = row.confirmed_at = None
