"""Deterministic PDF and DOCX renderers for :class:`ReportModel`.

PDF: reportlab with ``invariant=1`` (fixed creation date and document ID derived from content),
fixed producer/creator strings, built-in fonts only.
DOCX: python-docx, core properties set from the model, then the ZIP is rewritten with entries in a
fixed order, a fixed 1980-01-01 timestamp and fixed compression, so two runs produce the same bytes.
"""
from __future__ import annotations

import hashlib
import io
import zipfile
from datetime import datetime, timezone
from typing import Any

from .model import ReportModel

SEV_COLOR = {"critical": "#8B0000", "high": "#B22222", "medium": "#B8860B", "low": "#2F4F4F", "info": "#555555"}


def _esc(s: Any) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_pdf(model: ReportModel) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buf = io.BytesIO()
    title = model.template.get("title", "Forensic Report")
    doc = SimpleDocTemplate(
        buf, pagesize=A4, invariant=1, title=f"{title} - {model.case['id']}", author=model.examiner["display_name"],
        subject=f"Case {model.case['id']}", creator="Veritas DFIR", producer="Veritas DFIR report builder",
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm, bottomMargin=20 * mm,
    )
    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontName="Helvetica", fontSize=9.5, leading=12.5)
    small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=9.5, fontName="Courier")
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontName="Helvetica-Bold", fontSize=14, spaceBefore=10)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=11, spaceBefore=8)
    grid = TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8E8E8")),
                       ("FONTNAME", (0, 0), (-1, -1), "Helvetica"), ("FONTSIZE", (0, 0), (-1, -1), 7.5), ("VALIGN", (0, 0), (-1, -1), "TOP")])

    def para(t: str, st=body) -> Paragraph:
        return Paragraph(_esc(t), st)

    def table(rows: list[list[Any]], widths: list[float]) -> Table:
        t = Table([[Paragraph(_esc(c), small) for c in r] for r in rows], colWidths=[w * mm for w in widths], repeatRows=1)
        t.setStyle(grid)
        return t

    story: list[Any] = [
        Paragraph(_esc(title), ss["Title"]),
        para(f"Case: {model.case['name']} ({model.case['id']})"),
        para(f"Examiner: {model.examiner['display_name']}    Reviewer(s): {', '.join(model.reviewer_names) or 'none'}"),
        para(f"Case state as of: {model.generated_at}    Custody ledger head: {model.custody['head_hash']}"),
        Spacer(1, 6 * mm),
    ]
    for sec in model.template["sections"]:
        story.append(Paragraph(_esc(sec["heading"]), h1))
        if sec.get("intro"):
            story.append(para(model.fill(sec["intro"])))
        sid = sec["id"]
        if sid == "tools":
            story.append(table([["Tool", "Version", "SHA-256"]] + [[t["name"], t["version"], t.get("sha256") or "n/a"] for t in model.tools], [45, 30, 99]))
            if model.parity:
                story.append(Paragraph("Parser validation (field agreement with reference tools)", h2))
                story.append(table([["Parser", "Reference", "Fields", "Agreement"]] + [[p["parser"], p["reference"], str(p["fields"]), p["agreement"]] for p in model.parity], [35, 70, 20, 49]))
        elif sid == "evidence":
            story.append(table([["ID", "Name", "Kind", "Size", "SHA-256 / MD5", "Ingest ledger entry"]] +
                               [[e["id"], e["name"], e["kind"], str(e["size"]), f"{e['sha256']}\n{e['md5']}", e["ingest_entry_hash"]] for e in model.evidence], [16, 30, 13, 16, 55, 44]))
            story.append(Paragraph("Custody ledger (acquisition, ingestion, export and transformation entries)", h2))
            story.append(para(f"Ledger {model.custody['ledger_id']}: {model.custody['entry_count']} entries, including {model.custody['access_count']} recorded evidence accesses."))
            story.append(table([["Seq", "Time (UTC)", "Actor", "Kind", "Evidence", "Purpose", "Entry hash"]] +
                               [[str(e["seq"]), e["timestamp"], e["actor"], e["kind"], e["evidence_id"] or "", e["purpose"], e["entry_hash"]] for e in model.custody["entries"]],
                               [10, 30, 20, 15, 16, 35, 48]))
        elif sid == "findings":
            if not model.findings:
                story.append(para("No findings were approved for inclusion."))
            for i, f in enumerate(model.findings, 1):
                block = [
                    Paragraph(f"<font color='{SEV_COLOR.get(f['severity'], '#000000')}'>6.{i} [{_esc(f['severity'].upper())}] {_esc(f['title'])}</font>", h2),
                    para(f["description"]),
                    para(f"Examiner rationale: {f['examiner_rationale'] or 'n/a'}"),
                    para(f"Confirmed by {f['confirmed_by']}; approved by {f['approved_by']}. Reviewer comment: {f['reviewer_comment'] or 'none'}."),
                    para(f"Period: {f['first']} to {f['last']}. ATT&CK: {', '.join(f['attack_techniques']) or 'n/a'}."),
                ]
                story.append(KeepTogether(block))
                if f["artifacts"]:
                    story.append(table([["Time (UTC)", "Type", "Artifact", "Evidence / path / offset", "Ledger entry"]] +
                                       [[a["timestamp"] + "\n" + a["timestamp_desc"], a["data_type"], a["message"], f"{a['evidence_id']} {a['evidence_sha256'][:16]}...\n{a['evidence_path']} @ {a['offset']}", a["ledger_entry_hash"]] for a in f["artifacts"]],
                                       [27, 25, 50, 42, 30]))
                    if f["artifact_total"] > len(f["artifacts"]):
                        story.append(para(f"{f['artifact_total'] - len(f['artifacts'])} further supporting artifacts are listed in the case export."))
        elif sid == "limitations":
            for l in model.limitations_extra:
                story.append(para(f"- {l}"))
        elif sid == "attestation":
            story.append(Spacer(1, 12 * mm))
            story.append(para("Signature: ______________________________    Date: ________________"))
            story.append(para(f"Report state hash: {model.state_hash()}", small))
        if sid == "findings":
            story.append(PageBreak())

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.drawString(18 * mm, 10 * mm, f"Veritas DFIR | {model.case['id']} | state {model.state_hash()[:16]}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def normalize_zip(data: bytes) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(data))
    out = io.BytesIO()
    names = src.namelist()
    # [Content_Types].xml must stay first for Office compatibility; the rest sorted.
    ordered = [n for n in names if n == "[Content_Types].xml"] + sorted(n for n in names if n != "[Content_Types].xml")
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as dst:
        for n in ordered:
            zi = zipfile.ZipInfo(n, date_time=FIXED_ZIP_TIME)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            zi.create_system = 0
            dst.writestr(zi, src.read(n))
    return out.getvalue()


def render_docx(model: ReportModel) -> bytes:
    from docx import Document
    from docx.shared import Pt

    doc = Document()
    fixed = datetime.fromisoformat(model.generated_at.replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
    cp = doc.core_properties
    cp.author = model.examiner["display_name"]
    cp.title = f"{model.template.get('title')} - {model.case['id']}"
    cp.subject = f"Case {model.case['id']}"
    cp.created = fixed
    cp.modified = fixed
    cp.last_modified_by = model.examiner["display_name"]
    cp.revision = 1
    cp.identifier = model.state_hash()
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10)

    def tbl(rows: list[list[str]]) -> None:
        t = doc.add_table(rows=len(rows), cols=len(rows[0]))
        t.style = "Table Grid"
        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                t.cell(r, c).text = str(val)

    doc.add_heading(model.template.get("title", "Forensic Report"), 0)
    doc.add_paragraph(f"Case: {model.case['name']} ({model.case['id']})")
    doc.add_paragraph(f"Examiner: {model.examiner['display_name']}    Reviewer(s): {', '.join(model.reviewer_names) or 'none'}")
    doc.add_paragraph(f"Case state as of: {model.generated_at}    Custody ledger head: {model.custody['head_hash']}")
    for sec in model.template["sections"]:
        doc.add_heading(sec["heading"], 1)
        if sec.get("intro"):
            doc.add_paragraph(model.fill(sec["intro"]))
        sid = sec["id"]
        if sid == "tools":
            tbl([["Tool", "Version", "SHA-256"]] + [[t["name"], t["version"], t.get("sha256") or "n/a"] for t in model.tools])
            if model.parity:
                doc.add_heading("Parser validation", 2)
                tbl([["Parser", "Reference", "Fields", "Agreement"]] + [[p["parser"], p["reference"], str(p["fields"]), p["agreement"]] for p in model.parity])
        elif sid == "evidence":
            tbl([["ID", "Name", "Kind", "Size", "SHA-256", "MD5", "Ingest ledger entry"]] + [[e["id"], e["name"], e["kind"], str(e["size"]), e["sha256"], e["md5"], e["ingest_entry_hash"]] for e in model.evidence])
            doc.add_heading("Custody ledger", 2)
            doc.add_paragraph(f"Ledger {model.custody['ledger_id']}: {model.custody['entry_count']} entries, {model.custody['access_count']} recorded evidence accesses.")
            tbl([["Seq", "Time (UTC)", "Actor", "Kind", "Evidence", "Purpose", "Entry hash"]] + [[str(e["seq"]), e["timestamp"], e["actor"], e["kind"], e["evidence_id"] or "", e["purpose"], e["entry_hash"]] for e in model.custody["entries"]])
        elif sid == "findings":
            if not model.findings:
                doc.add_paragraph("No findings were approved for inclusion.")
            for i, f in enumerate(model.findings, 1):
                doc.add_heading(f"6.{i} [{f['severity'].upper()}] {f['title']}", 2)
                doc.add_paragraph(f["description"])
                doc.add_paragraph(f"Examiner rationale: {f['examiner_rationale'] or 'n/a'}")
                doc.add_paragraph(f"Confirmed by {f['confirmed_by']}; approved by {f['approved_by']}. Reviewer comment: {f['reviewer_comment'] or 'none'}.")
                doc.add_paragraph(f"Period: {f['first']} to {f['last']}. ATT&CK: {', '.join(f['attack_techniques']) or 'n/a'}.")
                if f["artifacts"]:
                    tbl([["Time (UTC)", "Type", "Artifact", "Evidence", "Path @ offset", "Ledger entry"]] + [[a["timestamp"], a["data_type"], a["message"], f"{a['evidence_id']} {a['evidence_sha256']}", f"{a['evidence_path']} @ {a['offset']}", a["ledger_entry_hash"]] for a in f["artifacts"]])
        elif sid == "limitations":
            for l in model.limitations_extra:
                doc.add_paragraph(l, style="List Bullet")
        elif sid == "attestation":
            doc.add_paragraph("Signature: ______________________________    Date: ________________")
            doc.add_paragraph(f"Report state hash: {model.state_hash()}")
    buf = io.BytesIO()
    doc.save(buf)
    return normalize_zip(buf.getvalue())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
