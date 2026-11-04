"""macOS Transparency, Consent and Control database (``TCC.db``).

``access`` table: service, client, client_type, allowed (pre-Big Sur) or auth_value/auth_reason
(Big Sur+), prompt_count, last_modified (Unix seconds) -> ``macos:tcc_entry``
(Content Modification Time). ``attrs.allowed`` is normalised to a bool: ``allowed = 1`` or
``auth_value = 2`` (allowed) / 3 (limited).
"""
from __future__ import annotations

import pathlib
from typing import Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.parsers.sqlite_safe import col, columns, has_table, is_sqlite, open_sqlite, rows, to_int
from veritas.timeline.schema import NS, Desc, Event

AUTH_VALUES = {0: "denied", 1: "unknown", 2: "allowed", 3: "limited"}
AUTH_REASONS = {1: "error", 2: "user_consent", 3: "user_set", 4: "system_set", 5: "service_policy", 6: "mdm_policy",
                7: "override_policy", 8: "missing_usage_string", 9: "prompt_timeout", 10: "preflight_unknown",
                11: "entitled", 12: "app_type_policy"}
CLIENT_TYPES = {0: "bundle_identifier", 1: "absolute_path"}


class TccParser(BaseParser):
    name = "macos_tcc"
    version = "1.0"
    source_short = "LOG"
    source_long = "macOS TCC"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return is_sqlite(head_bytes) and pathlib.Path(path).name.lower().startswith("tcc")

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            if not has_table(conn, "access"):
                raise ParserError("macos_tcc: no access table")
            acols = set(columns(conn, "access"))
            for idx, row in enumerate(rows(conn, "SELECT rowid AS rid, * FROM access ORDER BY rowid"), 1):
                try:
                    if "auth_value" in acols:
                        av = to_int(col(row, "auth_value"))
                        allowed = av in (2, 3)
                        decision = AUTH_VALUES.get(av, str(av))
                    else:
                        allowed = bool(to_int(col(row, "allowed"), 0))
                        decision = "allowed" if allowed else "denied"
                    ctype = to_int(col(row, "client_type"))
                    attrs = {
                        "service": col(row, "service"), "client": col(row, "client"),
                        "client_type": CLIENT_TYPES.get(ctype, ctype), "allowed": allowed, "decision": decision,
                        "auth_reason": AUTH_REASONS.get(to_int(col(row, "auth_reason"), -1)) if "auth_reason" in acols else None,
                        "prompt_count": to_int(col(row, "prompt_count")),
                        "indirect_object_identifier": col(row, "indirect_object_identifier"),
                    }
                    lm = to_int(col(row, "last_modified"))
                    msg = f"TCC {attrs['service']} {decision} for {attrs['client']}"
                    yield self.event("macos:tcc_entry", Desc.MODIFICATION, msg, lm * NS if lm else None,
                                     offset=to_int(col(row, "rid"), idx) or idx, attrs=attrs)
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"row {idx}: {exc}")


PARSERS = [TccParser]
