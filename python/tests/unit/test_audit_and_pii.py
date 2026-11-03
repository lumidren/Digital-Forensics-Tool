from datetime import datetime, timezone

from veritas.audit.log import AuditLog, scrub, verify
from veritas.pii.redact import Redactor, can_unmask, luhn_ok
from veritas.timeline.schema import Desc, Event


def test_audit_chain_append_and_verify(tmp_path):
    log = AuditLog(tmp_path / "audit.db", clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))
    log.append("alice", "case.create", case_id="C1", detail={"name": "x", "password": "hunter2"})
    log.append("bob", "evidence.read", case_id="C1", target="abc", detail={"bytes": 10})
    rows = log.export()
    assert rows[0]["detail"]["password"] == "[redacted]"
    assert rows[1]["prev_hash"] == rows[0]["row_hash"]
    ok, failures = verify(rows)
    assert ok and not failures
    rows[0]["detail"]["name"] = "y"
    ok, failures = verify(rows)
    assert not ok and any("row_hash" in f for f in failures)
    rows2 = log.export()
    del rows2[0]
    ok, failures = verify(rows2)
    assert not ok
    assert [r.actor for r in log.rows(actor="bob")] == ["bob"]


def test_scrub_nested():
    assert scrub({"a": {"api_key": "k", "x": 1}, "Authorization": "t"}) == {"a": {"api_key": "[redacted]", "x": 1}, "Authorization": "[redacted]"}


def test_luhn():
    assert luhn_ok("4111 1111 1111 1111")
    assert not luhn_ok("4111 1111 1111 1112")


def test_redactor_masks_consistently():
    r = Redactor(b"case-key")
    text = "mail bob@example.com and alice@example.org card 4111-1111-1111-1111 ssn 123-45-6789 ip 10.0.0.1"
    out, spans = r.redact_text(text)
    kinds = [s.kind for s in spans]
    assert kinds == ["EMAIL", "EMAIL", "CARD", "SSN"]
    assert "bob@example.com" not in out and "[EMAIL:" in out and "10.0.0.1" in out
    again, _ = r.redact_text("bob@example.com")
    assert again in out
    r2 = Redactor(b"case-key", include_ips=True)
    assert "10.0.0.1" not in r2.redact_text(text)[0]
    r3 = Redactor(b"other-key")
    assert r3.redact_text("bob@example.com")[0] != again


def test_redact_event_is_copy():
    e = Event(data_type="x", timestamp_desc=Desc.EVENT, message="call 555-123-4567 now", attrs={"to": "bob@example.com", "n": [1, "a@b.io"]})
    red = Redactor(b"k").redact_event(e)
    assert "bob@example.com" not in red.attrs["to"] and "a@b.io" not in red.attrs["n"][1]
    assert e.attrs["to"] == "bob@example.com"
    assert "[PHONE:" in red.message


def test_unmask_roles():
    assert can_unmask({"reviewer"}) and can_unmask({"pii.unmask"}) and not can_unmask({"examiner"})
