"""Structure-based detection of cloud log formats.

``select(path, head_bytes)`` looks at the first bytes of a file (gzip is inflated on the fly) and
returns the matching :class:`CloudParser` or ``None``. The file name is only a tie-breaker; the
structure of the content decides.
"""
from __future__ import annotations

import os
import zlib
from dataclasses import dataclass
from typing import Callable

from . import aws_cloudtrail, aws_elb, aws_s3, azure, gws, m365
from .base import (
    GZIP_MAGIC,
    ParseResult,
    ParserError,
    apply_provenance,
    decode_text,
    load_bytes,
    provenance_fields,
)

HEAD_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class CloudParser:
    name: str
    data_types: tuple[str, ...]
    parse: Callable[..., ParseResult]


PARSERS: dict[str, CloudParser] = {
    p.name: p
    for p in (
        CloudParser("aws_cloudtrail", (aws_cloudtrail.DATA_TYPE,), aws_cloudtrail.parse),
        CloudParser("aws_s3_access", (aws_s3.DATA_TYPE,), aws_s3.parse),
        CloudParser("aws_elb_access", (aws_elb.DATA_TYPE,), aws_elb.parse),
        CloudParser("azure_activity", (azure.ACTIVITY,), azure.parse_activity_log),
        CloudParser("azure_entra_audit", (azure.ENTRA_AUDIT,), azure.parse_entra_audit),
        CloudParser("azure_entra_signin", (azure.ENTRA_SIGNIN,), azure.parse_entra_signin),
        CloudParser("azure_appgw", (azure.APPGW,), azure.parse_appgw),
        CloudParser("gws_reports", (gws.DATA_TYPE,), gws.parse),
        CloudParser("m365_ual", (m365.DATA_TYPE,), m365.parse),
    )
}


def _inflate_head(head: bytes) -> bytes:
    if head[:2] != GZIP_MAGIC:
        return head
    try:
        return zlib.decompressobj(wbits=31).decompress(head, HEAD_BYTES)
    except zlib.error:
        return b""


def _json_keys(text: str) -> set[str]:
    """Collect the quoted keys visible in a (possibly truncated) JSON head."""
    keys: set[str] = set()
    i = 0
    n = len(text)
    while i < n:
        j = text.find('"', i)
        if j < 0:
            break
        k = text.find('"', j + 1)
        while k > 0 and text[k - 1] == "\\":
            k = text.find('"', k + 1)
        if k < 0:
            break
        rest = text[k + 1 : k + 4].lstrip()
        if rest.startswith(":"):
            keys.add(text[j + 1 : k])
        i = k + 1
    return keys


def _select_json(text: str) -> str | None:
    keys = _json_keys(text)
    if "eventName" in keys and ("eventSource" in keys or "eventVersion" in keys):
        return "aws_cloudtrail"
    if "activityDateTime" in keys and ("activityDisplayName" in keys or "initiatedBy" in keys):
        return "azure_entra_audit"
    if "createdDateTime" in keys and ({"userPrincipalName", "appDisplayName", "conditionalAccessStatus"} & keys):
        return "azure_entra_signin"
    if "ApplicationGatewayAccess" in text or "ApplicationGatewayAccessLog" in text:
        return "azure_appgw"
    if "applicationName" in keys and "actor" in keys:
        return "gws_reports"
    if "CreationTime" in keys and "Operation" in keys:
        return "m365_ual"
    if "AuditData" in keys and ("CreationDate" in keys or "Operations" in keys or "Operation" in keys):
        return "m365_ual"
    if "operationName" in keys and ("time" in keys or "eventTimestamp" in keys):
        return "azure_activity"
    return None


def _select_lines(text: str) -> str | None:
    for line in text.splitlines()[:20]:
        if not line.strip():
            continue
        if aws_elb.looks_like(line):
            return "aws_elb_access"
        if aws_s3.looks_like(line):
            return "aws_s3_access"
        return None
    return None


def select(path: str | os.PathLike[str] | None, head_bytes: bytes) -> CloudParser | None:
    """Return the parser for a file whose first bytes are ``head_bytes`` (``path`` is advisory)."""
    if not isinstance(head_bytes, (bytes, bytearray, memoryview)):
        return None
    head = _inflate_head(bytes(head_bytes[:HEAD_BYTES]))
    if not head:
        return None
    text = decode_text(head).lstrip()
    if not text:
        return None
    name: str | None
    if text[0] in "[{":
        name = _select_json(text)
    else:
        first_line = text.splitlines()[0]
        if "AuditData" in first_line and "," in first_line:
            name = "m365_ual"
        else:
            name = _select_lines(text)
    return PARSERS.get(name) if name else None


def parse_auto(source, provenance=None, *, evidence_path: str = "", evidence_sha256: str = "") -> ParseResult:
    """Detect and parse. ``provenance`` is a ``veritas.parsers.base.Provenance`` (or any object with
    ``evidence_path`` / ``evidence_sha256``). Iterating the returned result yields Events.

    Raises :class:`ParserError` when no format matches.
    """
    evidence_path, evidence_sha256 = provenance_fields(provenance, evidence_path, evidence_sha256)
    data = load_bytes(source)
    path = os.fspath(source) if isinstance(source, (str, os.PathLike)) else None
    parser = select(path, data[:HEAD_BYTES])
    if parser is None:
        raise ParserError("unrecognised cloud log format")
    result = parser.parse(data, evidence_path=evidence_path or (path or "").replace("\\", "/"),
                          evidence_sha256=evidence_sha256)
    return apply_provenance(result, provenance)


__all__ = ["CloudParser", "PARSERS", "select", "parse_auto"]
