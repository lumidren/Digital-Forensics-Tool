#!/usr/bin/env python3
"""Render the technical paper (a restricted Markdown dialect) to PDF with reportlab.

Supported: '#', '##', '###' headings; paragraphs; '*' and '1.' lists; pipe tables; fenced code
blocks; **bold**, *italic* and `code` inline. Output is deterministic (reportlab invariant mode).

    python scripts/md_to_pdf.py docs/paper/veritas-dfir.md docs/paper/veritas-dfir.pdf
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import ListFlowable, ListItem, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle


def inline(text: str) -> str:
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"`([^`]+)`", r'<font face="Courier" size="8.5">\1</font>', text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<![\w*])\*([^*\s][^*]*?)\*(?![\w*])", r"<i>\1</i>", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text


def build(md: str, out: Path) -> int:
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontName="Times-Roman", fontSize=10.5, leading=14, alignment=TA_JUSTIFY, spaceAfter=5)
    title = ParagraphStyle("t", parent=ss["Title"], fontName="Times-Bold", fontSize=17, leading=21, spaceAfter=6)
    author = ParagraphStyle("a", parent=body, alignment=TA_CENTER, fontSize=11, spaceAfter=12)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Times-Bold", fontSize=13, spaceBefore=10, spaceAfter=4)
    h3 = ParagraphStyle("h3", parent=ss["Heading3"], fontName="Times-Bold", fontSize=11, spaceBefore=6, spaceAfter=3)
    cap = ParagraphStyle("c", parent=body, fontSize=9, alignment=TA_CENTER, spaceBefore=2, spaceAfter=8)
    cell = ParagraphStyle("cell", parent=body, fontSize=8.5, leading=10.5, alignment=0, spaceAfter=0)
    code = ParagraphStyle("code", parent=ss["Code"], fontName="Courier", fontSize=7.8, leading=9.5, backColor=colors.HexColor("#F3F3F3"), borderPadding=4, spaceBefore=4, spaceAfter=8)

    story: list = []
    lines = md.splitlines()
    i = 0
    para: list[str] = []
    first_h1 = True

    def flush():
        if para:
            txt = " ".join(s.strip() for s in para)
            story.append(Paragraph(inline(txt), cap if txt.startswith("*Figure") or txt.startswith("*Table") else body))
            para.clear()

    while i < len(lines):
        ln = lines[i]
        if ln.startswith("```"):
            flush()
            j = i + 1
            block = []
            while j < len(lines) and not lines[j].startswith("```"):
                block.append(lines[j])
                j += 1
            story.append(Preformatted("\n".join(block), code))
            i = j + 1
            continue
        if ln.startswith("# "):
            flush()
            story.append(Paragraph(inline(ln[2:]), title))
            if first_h1 and i + 2 < len(lines) and lines[i + 2].strip():
                story.append(Paragraph(inline(lines[i + 2].strip()), author))
                i += 3
                first_h1 = False
                continue
        elif ln.startswith("## "):
            flush()
            story.append(Paragraph(inline(ln[3:]), h2))
        elif ln.startswith("### "):
            flush()
            story.append(Paragraph(inline(ln[4:]), h3))
        elif ln.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
                    rows.append([Paragraph(inline(c), cell) for c in cells])
                i += 1
            ncol = len(rows[0])
            width = 170 * mm
            first = 0.42 if ncol == 2 else (0.34 if ncol == 4 else 0.3)
            widths = [width * first] + [width * (1 - first) / (ncol - 1)] * (ncol - 1)
            t = Table(rows, colWidths=widths, repeatRows=1, hAlign="CENTER")
            t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E6E6E6")),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
            story.append(Spacer(1, 3))
            story.append(t)
            continue
        elif re.match(r"^(\*|\d+\.) ", ln):
            flush()
            numbered = bool(re.match(r"^\d+\. ", ln))
            items = []
            while i < len(lines) and (re.match(r"^(\*|\d+\.) ", lines[i]) or (lines[i].startswith("  ") and lines[i].strip())):
                if re.match(r"^(\*|\d+\.) ", lines[i]):
                    items.append(re.sub(r"^(\*|\d+\.) ", "", lines[i]))
                else:
                    items[-1] += " " + lines[i].strip()
                i += 1
            story.append(ListFlowable([ListItem(Paragraph(inline(t), body), leftIndent=12) for t in items], bulletType="1" if numbered else "bullet",
                                      start="1" if numbered else None, leftIndent=14, bulletFontSize=8))
            continue
        elif not ln.strip():
            flush()
        else:
            para.append(ln)
        i += 1
    flush()

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Times-Roman", 8.5)
        canvas.drawCentredString(A4[0] / 2, 12 * mm, f"Veritas DFIR technical paper  |  {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(out), pagesize=A4, invariant=1, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=20 * mm, bottomMargin=20 * mm,
                            title="Veritas DFIR: Verifiable Evidence Handling and Validated Artifact Parsing", author="lumidren", creator="scripts/md_to_pdf.py", producer="reportlab")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return doc.page


if __name__ == "__main__":
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    pages = build(src.read_text(encoding="utf-8"), dst)
    print(f"wrote {dst} ({pages} pages)")
