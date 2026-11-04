"""Report determinism: the same case state must produce byte-identical PDF and DOCX."""
import io
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from veritas.reporting.model import build_model, load_template
from veritas.reporting.render import normalize_zip, render_docx, render_pdf, sha256
from veritas.reporting.stix import stix_bundle, timeline_csv, timeline_plaso_json_line
from veritas.timeline.schema import Desc, Event

TPL_DIR = Path(__file__).resolve().parents[2] / "veritas" / "reporting" / "templates"


def state():
    evidence = [{"id": "EV-1", "name": "laptop.E01", "kind": "disk", "size": 1024, "sha256": "a" * 64, "md5": "b" * 32, "sha3_256": "c" * 64, "ingest_entry_hash": "d" * 64}]
    ledger = [
        {"seq": 0, "ledger_id": "L-C1", "timestamp": "2026-01-01T00:00:00Z", "actor": "alice", "kind": "genesis", "evidence_id": None, "purpose": "ledger created", "entry_hash": "0" * 63 + "1"},
        {"seq": 1, "ledger_id": "L-C1", "timestamp": "2026-01-02T00:00:00Z", "actor": "alice", "kind": "ingest", "evidence_id": "EV-1", "purpose": "stored", "entry_hash": "d" * 64},
        {"seq": 2, "ledger_id": "L-C1", "timestamp": "2026-01-03T00:00:00Z", "actor": "veritas-pipeline", "kind": "access", "evidence_id": "EV-1", "purpose": "parse", "entry_hash": "e" * 64},
    ]
    findings = [{"id": "F1", "title": "Lateral movement 10.0.0.5 -> WS01", "description": "RDP logon", "severity": "high", "category": "lateral-movement", "attack_techniques": ["T1021.001"],
                 "event_ids": [7, 3], "examiner_rationale": "Matches RDP logs", "confirmed_by": "alice", "approved_by": "bob", "reviewer_comment": "ok", "first_ns": 1_700_000_000_000_000_000, "last_ns": 1_700_000_100_000_000_000}]
    events = {3: {"timestamp": 1_700_000_000_000_000_000, "timestamp_desc": Desc.EVENT, "data_type": "windows:evtx:record", "message": "[4624] logon type 10", "evidence_sha256": "a" * 64, "evidence_path": "Security.evtx", "offset": 99, "parser": "evtx", "parser_version": "0.1.0"},
              7: {"timestamp": 1_700_000_100_000_000_000, "timestamp_desc": Desc.EVENT, "data_type": "windows:evtx:record", "message": "[1149] rdp auth", "evidence_sha256": "a" * 64, "evidence_path": "RCM.evtx", "offset": 5, "parser": "evtx", "parser_version": "0.1.0"}}
    return dict(template=load_template(TPL_DIR), case={"id": "C1", "name": "Intrusion", "description": "Scope text"}, examiner={"id": "alice", "display_name": "Alice Examiner"},
                reviewers=["bob"], evidence=evidence, ledger_entries=ledger, findings=findings, events_by_id=events,
                tools=[{"name": "veritas-api", "version": "0.1.0", "sha256": "f" * 64}], parity=[{"parser": "evtx", "reference": "libevtx", "fields": 12, "agreement": "100.00%"}],
                limitations_extra=["Memory not acquired"])


def test_model_links_artifacts_to_hash_and_ledger():
    m = build_model(**state())
    f = m.findings[0]
    assert [a["event_id"] for a in f["artifacts"]] == [3, 7]
    assert all(a["ledger_entry_hash"] == "d" * 64 and a["evidence_sha256"] == "a" * 64 and a["evidence_id"] == "EV-1" for a in f["artifacts"])
    assert m.generated_at == "2026-01-03T00:00:00Z" and m.custody["access_count"] == 1
    assert len(m.state_hash()) == 64
    assert m.fill("{case_id} {approved_count}") == "C1 1"
    with pytest.raises(KeyError):
        m.fill("{nope}")


def test_pdf_and_docx_are_deterministic():
    a, b = build_model(**state()), build_model(**state())
    assert a.state_hash() == b.state_hash()
    pdf1, pdf2 = render_pdf(a), render_pdf(b)
    assert pdf1.startswith(b"%PDF") and sha256(pdf1) == sha256(pdf2)
    docx1, docx2 = render_docx(a), render_docx(b)
    assert sha256(docx1) == sha256(docx2)
    z = zipfile.ZipFile(io.BytesIO(docx1))
    assert z.namelist()[0] == "[Content_Types].xml" and all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in z.infolist())
    assert b"Alice Examiner" in z.read("docProps/core.xml")


def test_state_change_changes_output():
    s = state()
    s["findings"][0]["reviewer_comment"] = "changed"
    assert build_model(**s).state_hash() != build_model(**state()).state_hash()


def test_template_validation(tmp_path):
    (tmp_path / "bad.yaml").write_text("name: bad\nsections:\n  - id: scope\n    heading: x\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_template(tmp_path, "bad")
    with pytest.raises(FileNotFoundError):
        load_template(tmp_path, "../etc")


def test_normalize_zip_idempotent():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("b.xml", "b")
        z.writestr("[Content_Types].xml", "t")
        z.writestr("a.xml", "a")
    n1 = normalize_zip(buf.getvalue())
    assert normalize_zip(n1) == n1 and zipfile.ZipFile(io.BytesIO(n1)).namelist() == ["[Content_Types].xml", "a.xml", "b.xml"]


def test_stix_and_exports():
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    iocs = [{"ioc_type": "domain", "value": "evil.example", "source": "manual", "tags": [], "hits": 2, "created": created},
            {"ioc_type": "sha256", "value": "a" * 64, "source": "vt", "tags": ["ransomware"], "hits": 0, "created": created},
            {"ioc_type": "regex", "value": "x+", "source": "m", "tags": [], "hits": 0, "created": created}]
    b1, b2 = stix_bundle("C1", "Case", iocs, "alice"), stix_bundle("C1", "Case", iocs, "alice")
    assert b1 == b2
    types = [o["type"] for o in b1["objects"]]
    assert types == ["identity", "indicator", "indicator", "report"]
    assert b1["objects"][1]["pattern"] == "[domain-name:value = 'evil.example']"
    stix2 = pytest.importorskip("stix2")
    parsed = stix2.parse(b1, allow_custom=False)
    assert len(parsed.objects) == 4
    e = Event(data_type="x", timestamp_desc=Desc.EVENT, message='m,"q"', timestamp=1_700_000_000_123_456_000, attrs={"b": 1, "a": 2})
    csv_text = timeline_csv([e])
    assert csv_text.splitlines()[1].startswith("2023-11-14T22:13:20.123456Z,")
    assert '"timestamp": 1700000000123456' in timeline_plaso_json_line(e)
