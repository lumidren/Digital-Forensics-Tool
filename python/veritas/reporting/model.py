"""Report model: a pure, deterministic projection of case state.

``build_model`` reads only what it is given (no clock, no randomness, sorted collections), so the
same case state always yields the same model and therefore the same ``state_hash``. Renderers in
``pdf.py`` and ``docx_render.py`` turn the model into bytes without adding variable data.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..custody.ledger import canonical_bytes
from ..timeline.schema import format_ns

_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


@dataclass(slots=True)
class ReportModel:
    template: dict[str, Any]
    case: dict[str, Any]
    examiner: dict[str, Any]
    reviewer_names: list[str]
    generated_at: str  # derived from case state, never the wall clock
    evidence: list[dict[str, Any]]
    custody: dict[str, Any]
    tools: list[dict[str, Any]]
    parity: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    limitations_extra: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "template": self.template, "case": self.case, "examiner": self.examiner, "reviewer_names": self.reviewer_names,
            "generated_at": self.generated_at, "evidence": self.evidence, "custody": self.custody, "tools": self.tools,
            "parity": self.parity, "findings": self.findings, "limitations_extra": self.limitations_extra,
        }

    def state_hash(self) -> str:
        return hashlib.sha256(canonical_bytes(_no_floats(self.to_dict()))).hexdigest()

    def fill(self, text: str) -> str:
        values = {
            "evidence_count": str(len(self.evidence)), "case_name": self.case["name"], "case_id": self.case["id"],
            "approved_count": str(len(self.findings)), "case_description": self.case.get("description") or "No scope statement recorded.",
            "examiner_name": self.examiner["display_name"],
        }

        def sub(m: re.Match) -> str:
            if m.group(1) not in values:
                raise KeyError(f"unknown template placeholder {{{m.group(1)}}}")
            return values[m.group(1)]

        return _PLACEHOLDER.sub(sub, text)


def _no_floats(v: Any) -> Any:
    if isinstance(v, float):
        return f"{v:.2f}"
    if isinstance(v, dict):
        return {k: _no_floats(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_no_floats(x) for x in v]
    return v


def load_template(directory: Path, name: str = "default") -> dict[str, Any]:
    path = directory / f"{name}.yaml"
    if not re.fullmatch(r"[a-z0-9_-]+", name) or not path.exists():
        raise FileNotFoundError(f"report template {name!r} not found")
    tpl = yaml.safe_load(path.read_text(encoding="utf-8"))
    ids = [s["id"] for s in tpl["sections"]]
    required = {"executive_summary", "scope", "methodology", "tools", "evidence", "findings", "limitations", "attestation"}
    missing = required - set(ids)
    if missing:
        raise ValueError(f"template {name} is missing required sections: {sorted(missing)}")
    return tpl


def build_model(*, template: dict[str, Any], case: dict[str, Any], examiner: dict[str, Any], reviewers: list[str], evidence: list[dict[str, Any]],
                ledger_entries: list[dict[str, Any]], findings: list[dict[str, Any]], events_by_id: dict[int, dict[str, Any]],
                tools: list[dict[str, Any]], parity: list[dict[str, Any]], limitations_extra: list[str] | None = None) -> ReportModel:
    ev_by_sha = {e["sha256"]: e for e in evidence}
    ingest_hash = {e["sha256"]: e["ingest_entry_hash"] for e in evidence}
    out_findings = []
    for f in sorted(findings, key=lambda f: (-_sev(f["severity"]), f["title"], f["id"])):
        refs = []
        for eid in sorted(f.get("event_ids", [])):
            e = events_by_id.get(eid)
            if e is None:
                continue
            sha = e.get("evidence_sha256", "")
            ev = ev_by_sha.get(sha)
            refs.append({
                "event_id": eid, "timestamp": format_ns(e["timestamp"]) if e.get("timestamp") is not None else "n/a", "timestamp_desc": e.get("timestamp_desc", ""),
                "data_type": e.get("data_type", ""), "message": (e.get("message") or "")[:400], "evidence_id": ev["id"] if ev else "unknown",
                "evidence_sha256": sha, "evidence_path": e.get("evidence_path", ""), "offset": int(e.get("offset", 0)),
                "ledger_entry_hash": ingest_hash.get(sha, "not-ingested"), "parser": f"{e.get('parser', '')} {e.get('parser_version', '')}".strip(),
            })
        out_findings.append({
            "id": f["id"], "title": f["title"], "description": f["description"], "severity": f["severity"], "category": f["category"],
            "attack_techniques": sorted(f.get("attack_techniques", [])), "examiner_rationale": f.get("examiner_rationale", ""),
            "confirmed_by": f.get("confirmed_by"), "approved_by": f.get("approved_by"), "reviewer_comment": f.get("reviewer_comment", ""),
            "first": format_ns(f["first_ns"]) if f.get("first_ns") is not None else "n/a", "last": format_ns(f["last_ns"]) if f.get("last_ns") is not None else "n/a",
            "artifacts": refs[:200], "artifact_total": len(refs),
        })
    custody = {
        "ledger_id": ledger_entries[0]["ledger_id"] if ledger_entries else "",
        "entry_count": len(ledger_entries),
        "head_hash": ledger_entries[-1]["entry_hash"] if ledger_entries else "",
        "entries": [
            {"seq": e["seq"], "timestamp": e["timestamp"], "actor": e["actor"], "kind": e["kind"], "evidence_id": e.get("evidence_id"), "purpose": e["purpose"][:200], "entry_hash": e["entry_hash"]}
            for e in ledger_entries if e["kind"] in ("genesis", "acquire", "ingest", "export", "transform", "key_enrolled", "key_revoked", "anchor")
        ],
        "access_count": sum(1 for e in ledger_entries if e["kind"] == "access"),
    }
    # "generated_at" is the time of the latest state change that the report reflects.
    generated_at = max([e["timestamp"] for e in ledger_entries] or ["1970-01-01T00:00:00Z"])
    return ReportModel(
        template=template, case={k: case[k] for k in sorted(case)}, examiner=examiner, reviewer_names=sorted(set(reviewers)), generated_at=generated_at,
        evidence=sorted(evidence, key=lambda e: e["id"]), custody=custody, tools=sorted(tools, key=lambda t: t["name"]), parity=sorted(parity, key=lambda p: p["parser"]),
        findings=out_findings, limitations_extra=sorted(limitations_extra or []),
    )


def _sev(s: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0)
