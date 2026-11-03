"""PII detection and redaction with role-based unmasking.

Detected spans are replaced with a typed mask such as ``[EMAIL:3f2a]`` where the suffix is a
short keyed hash, so the same value masks to the same token across a case (analysts can still
correlate) without exposing the value. Unmasking requires the ``pii.unmask`` permission and is
audited by the caller. THREAT:T5.3
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any, Callable

from ..timeline.schema import Event

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<![\w/])(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?![\w/])")
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}\b")


def luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if len(d) < 13:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@dataclass(frozen=True, slots=True)
class Detector:
    kind: str
    pattern: re.Pattern
    validate: Callable[[str], bool] = lambda s: True


DETECTORS: tuple[Detector, ...] = (
    Detector("EMAIL", _EMAIL),
    Detector("SSN", _SSN),
    Detector("CARD", _CARD, luhn_ok),
    Detector("IBAN", _IBAN),
    Detector("PHONE", _PHONE, lambda s: 9 <= sum(c.isdigit() for c in s) <= 15),
)

OPTIONAL_DETECTORS: dict[str, Detector] = {"IPV4": Detector("IPV4", _IPV4)}


@dataclass(slots=True)
class Span:
    kind: str
    start: int
    end: int
    value: str


class Redactor:
    def __init__(self, case_key: bytes, kinds: set[str] | None = None, include_ips: bool = False):
        self._key = case_key
        dets = list(DETECTORS)
        if include_ips:
            dets.append(OPTIONAL_DETECTORS["IPV4"])
        self._detectors = [d for d in dets if kinds is None or d.kind in kinds]

    def token(self, kind: str, value: str) -> str:
        mac = hmac.new(self._key, f"{kind}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()[:6]
        return f"[{kind}:{mac}]"

    def find(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for d in self._detectors:
            for m in d.pattern.finditer(text):
                if d.validate(m.group(0)):
                    spans.append(Span(d.kind, m.start(), m.end(), m.group(0)))
        spans.sort(key=lambda s: (s.start, -(s.end - s.start)))
        merged: list[Span] = []
        for s in spans:
            if merged and s.start < merged[-1].end:
                continue
            merged.append(s)
        return merged

    def redact_text(self, text: str) -> tuple[str, list[Span]]:
        spans = self.find(text)
        if not spans:
            return text, []
        out, last = [], 0
        for s in spans:
            out.append(text[last:s.start])
            out.append(self.token(s.kind, s.value))
            last = s.end
        out.append(text[last:])
        return "".join(out), spans

    def redact_value(self, v: Any) -> Any:
        if isinstance(v, str):
            return self.redact_text(v)[0]
        if isinstance(v, list):
            return [self.redact_value(x) for x in v]
        if isinstance(v, dict):
            return {k: self.redact_value(x) for k, x in v.items()}
        return v

    def redact_event(self, e: Event) -> Event:
        """Return a redacted copy; the stored event is never modified."""
        return Event(
            data_type=e.data_type, timestamp_desc=e.timestamp_desc, message=self.redact_text(e.message)[0], timestamp=e.timestamp,
            source_short=e.source_short, source_long=e.source_long, evidence_sha256=e.evidence_sha256,
            evidence_path=self.redact_text(e.evidence_path)[0], offset=e.offset, parser=e.parser, parser_version=e.parser_version,
            host=e.host, user=e.user, timezone=e.timezone, skew_ns=e.skew_ns, attrs=self.redact_value(e.attrs),
        )


def can_unmask(roles: set[str]) -> bool:
    return bool(roles & {"admin", "reviewer"}) or "pii.unmask" in roles
