"""Findings model and engine.

Analytics rules *propose* findings. A proposed finding carries the rule that produced it, the
events it rests on, and a confidence. It becomes part of the record only after an examiner
confirms it; a reviewer other than the confirming examiner must approve it before it can be
included in a report. Nothing in this module can set a finding to ``confirmed``. THREAT:T5.4
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Protocol

from ..timeline.schema import Event
from ..timeline.store import StoredEvent

PROPOSED, CONFIRMED, REJECTED, APPROVED = "proposed", "confirmed", "rejected", "approved"
SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(slots=True)
class Finding:
    rule: str
    title: str
    description: str
    severity: str
    confidence: float  # 0..1, rounded to 2 decimals
    category: str
    attack_techniques: list[str] = field(default_factory=list)
    event_ids: list[int] = field(default_factory=list)
    evidence_sha256: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    first_ns: int | None = None
    last_ns: int | None = None
    details: dict[str, Any] = field(default_factory=dict)
    state: str = PROPOSED
    finding_id: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity}")
        self.confidence = round(max(0.0, min(1.0, self.confidence)), 2)
        self.attack_techniques = sorted(set(self.attack_techniques))
        self.event_ids = sorted(set(self.event_ids))
        self.evidence_sha256 = sorted(set(self.evidence_sha256))
        self.hosts = sorted(set(h for h in self.hosts if h))
        self.users = sorted(set(u for u in self.users if u))
        if not self.finding_id:
            payload = json.dumps([self.rule, self.title, self.hosts, self.users, self.event_ids, self.details], sort_keys=True, separators=(",", ":"), default=str)
            self.finding_id = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id, "rule": self.rule, "title": self.title, "description": self.description,
            "severity": self.severity, "confidence": self.confidence, "category": self.category,
            "attack_techniques": self.attack_techniques, "event_ids": self.event_ids, "evidence_sha256": self.evidence_sha256,
            "hosts": self.hosts, "users": self.users, "first_ns": self.first_ns, "last_ns": self.last_ns,
            "details": self.details, "state": self.state,
        }


class Rule(Protocol):
    name: str

    def run(self, events: Iterable[StoredEvent]) -> Iterator[Finding]: ...


def span(events: list[StoredEvent]) -> tuple[int | None, int | None]:
    ts = [e.event.timestamp for e in events if e.event.timestamp is not None]
    return (min(ts), max(ts)) if ts else (None, None)


def mk_finding(rule: str, title: str, description: str, severity: str, confidence: float, category: str, events: list[StoredEvent], techniques: list[str], details: dict[str, Any] | None = None) -> Finding:
    first, last = span(events)
    return Finding(
        rule=rule, title=title, description=description, severity=severity, confidence=confidence, category=category,
        attack_techniques=techniques, event_ids=[e.id for e in events], evidence_sha256=[e.event.evidence_sha256 for e in events],
        hosts=[e.event.host or "" for e in events], users=[e.event.user or "" for e in events], first_ns=first, last_ns=last, details=details or {},
    )


class FindingsEngine:
    """Runs every registered rule over a case's events and returns proposed findings."""

    def __init__(self, rules: list[Rule] | None = None):
        from . import antiforensics, execution, lateral, persistence, provenance, timestomp, user_activity

        self.rules: list[Rule] = rules or [
            timestomp.TimestompRule(), antiforensics.AntiForensicsRule(), execution.ExecutionCorrelationRule(),
            lateral.LateralMovementRule(), persistence.PersistenceInventoryRule(), user_activity.UserActivityRule(),
            provenance.FileProvenanceRule(),
        ]

    def run(self, events: Iterable[StoredEvent]) -> list[Finding]:
        cached = list(events)
        out: list[Finding] = []
        for rule in self.rules:
            for f in rule.run(cached):
                f.state = PROPOSED  # rules can never assert
                out.append(f)
        out.sort(key=lambda f: (SEVERITIES.index(f.severity), -f.confidence, f.rule, f.title))
        out.reverse()
        return out


def iter_stored(events: Iterable[Event]) -> Iterator[StoredEvent]:
    """Wrap plain events with sequential ids for tests and offline runs."""
    for i, e in enumerate(events):
        yield StoredEvent(id=i, event=e)
