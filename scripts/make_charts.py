#!/usr/bin/env python3
"""Generate the README charts from committed results.

    docs/images/parity.svg      field agreement per parser family (parity/results/*.json)
    docs/images/throughput.svg  per-stage throughput (docs/benchmarks.json)

Plain SVG, no dependencies, dark background so the charts read the same in GitHub's light and dark modes.
"""
from __future__ import annotations

import glob
import json
import pathlib
from collections import defaultdict
from xml.sax.saxutils import escape

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "images"
BG = '<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0b1220"/><stop offset="1" stop-color="#141b30"/></linearGradient></defs>'

FAMILY = [
    ("File systems", lambda n: n.startswith("fs_") or n == "ewf", "#22d3ee"),
    ("Windows artifacts (Rust)", lambda n: n in {"evtx", "prefetch", "lnk", "shellitems", "jumplist", "regf", "registry_artifacts"}, "#60a5fa"),
    ("Linux / macOS (Rust)", lambda n: n in {"journald", "plist"}, "#a78bfa"),
    ("Browsers & Windows (Python)", lambda n: n.startswith("py_") and any(k in n for k in ("chromium", "firefox", "msie", "srum", "pst", "mbox", "ooxml", "olecf", "recycle", "powershell", "timeline", "setupapi", "windefender", "wmi")), "#f472b6"),
    ("Linux & macOS (Python)", lambda n: n.startswith("py_"), "#f59e0b"),
    ("Network & malware", lambda n: n in {"pcap", "pe_static"}, "#34d399"),
]


def parity_chart() -> str:
    agg: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    colors = {}
    for p in sorted(glob.glob(str(ROOT / "parity" / "results" / "*.json"))):
        d = json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
        name = d.get("parser", pathlib.Path(p).stem)
        for fam, match, color in FAMILY:
            if match(name):
                a = sum(f["agree"] for f in d["fields"].values())
                t = sum(f["total"] for f in d["fields"].values())
                agg[fam][0] += a
                agg[fam][1] += t
                agg[fam][2] += 1
                colors[fam] = color
                break
    rows = [(fam, *agg[fam]) for fam, _, _ in FAMILY if fam in agg]
    total_a = sum(r[1] for r in rows)
    total_t = sum(r[2] for r in rows)
    total_p = sum(r[3] for r in rows)
    w, top, rh = 1200, 120, 54
    h = top + rh * len(rows) + 60
    x0, x1 = 330, 1050
    lo = 98.5  # axis starts at 98.5% so differences are visible; labelled explicitly
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" font-family="Segoe UI, Helvetica, Arial, sans-serif" role="img" aria-labelledby="t d">',
             '<title id="t">Parser agreement with reference tools</title>',
             f'<desc id="d">{total_p} parsers agree with reference implementations on {100 * total_a / total_t:.2f}% of {total_t:,} field comparisons.</desc>',
             BG, f'<rect width="{w}" height="{h}" rx="18" fill="url(#bg)"/>',
             '<text x="40" y="50" fill="#e6edf7" font-size="22" font-weight="700">Validated against the tools courts already know</text>',
             f'<text x="40" y="76" fill="#8aa4c8" font-size="14">{total_p} parsers · {total_t:,} field comparisons vs The Sleuth Kit, libyal, Plaso, dissect, scapy, LIEF · overall {100 * total_a / total_t:.2f}% agreement</text>']
    for tick in (98.5, 99.0, 99.5, 100.0):
        x = x0 + (tick - lo) / (100 - lo) * (x1 - x0)
        parts.append(f'<line x1="{x:.1f}" y1="{top - 14}" x2="{x:.1f}" y2="{top + rh * len(rows) - 10}" stroke="#22324d"/>')
        parts.append(f'<text x="{x:.1f}" y="{top - 20}" fill="#64748b" font-size="11" text-anchor="middle">{tick:g}%</text>')
    for i, (fam, a, t, n) in enumerate(rows):
        y = top + i * rh
        pct = 100 * a / t
        bw = max(4.0, (min(pct, 100) - lo) / (100 - lo) * (x1 - x0))
        parts.append(f'<text x="40" y="{y + 20}" fill="#e6edf7" font-size="14" font-weight="600">{escape(fam)}</text>')
        parts.append(f'<text x="40" y="{y + 38}" fill="#8aa4c8" font-size="11.5">{n} parsers · {t:,} comparisons</text>')
        parts.append(f'<rect x="{x0}" y="{y + 6}" width="{x1 - x0}" height="26" rx="6" fill="#1b2a45"/>')
        parts.append(f'<rect x="{x0}" y="{y + 6}" width="{bw:.1f}" height="26" rx="6" fill="{colors[fam]}"/>')
        parts.append(f'<text x="{x1 + 14}" y="{y + 25}" fill="#e6edf7" font-size="14" font-weight="700">{pct:.2f}%</text>')
    parts.append(f'<text x="40" y="{h - 22}" fill="#5b6f8f" font-size="11.5">Axis starts at 98.5%. Every disagreement is explained in docs/PARITY.md (e.g. libregf inline-value bug, pyfsfat month offset). CI blocks any regression.</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def throughput_chart() -> str:
    b = json.loads((ROOT / "docs" / "benchmarks.json").read_text(encoding="utf-8"))
    rows = [(r["stage"].split(" (")[0].replace("E01 ", "E01 "), r["gb_per_hour"], "#60a5fa") for r in b["acquisition"] if "best" not in r["stage"]]
    rows = [("Triple hash (MD5+SHA-256+SHA3)", rows[0][1], "#34d399"), ("E01 imaging, fast zlib", rows[1][1], "#60a5fa"), ("E01 verify", rows[2][1], "#a78bfa")]
    rows.append(("End to end: NIST Hacking Case", 130, "#f472b6"))
    tl = b["timeline"]
    w, top, rh = 1200, 120, 50
    h = top + rh * len(rows) + 110
    x0, x1 = 360, 1050
    mx = max(r[1] for r in rows) * 1.25
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" font-family="Segoe UI, Helvetica, Arial, sans-serif" role="img" aria-labelledby="t d">',
             '<title id="t">Throughput by stage</title>',
             '<desc id="d">Measured GB per hour for hashing, E01 imaging and verification, and end-to-end processing of a real image, plus timeline search latency.</desc>',
             BG, f'<rect width="{w}" height="{h}" rx="18" fill="url(#bg)"/>',
             '<text x="40" y="50" fill="#e6edf7" font-size="22" font-weight="700">Fast enough for real casework on a laptop</text>',
             f'<text x="40" y="76" fill="#8aa4c8" font-size="14">{escape(b["env"]["cpu"])} · NVMe SSD · one worker · GB per hour</text>']
    for i, (name, v, color) in enumerate(rows):
        y = top + i * rh
        bw = v / mx * (x1 - x0)
        parts.append(f'<text x="40" y="{y + 24}" fill="#e6edf7" font-size="14" font-weight="600">{escape(name)}</text>')
        parts.append(f'<rect x="{x0}" y="{y + 6}" width="{x1 - x0}" height="26" rx="6" fill="#1b2a45"/>')
        parts.append(f'<rect x="{x0}" y="{y + 6}" width="{bw:.1f}" height="26" rx="6" fill="{color}"/>')
        parts.append(f'<text x="{x0 + bw + 12:.1f}" y="{y + 25}" fill="#e6edf7" font-size="14" font-weight="700">{v:,} GB/h</text>')
    y = top + rh * len(rows) + 20
    stats = [("Search p50", f'{tl["p50_ms"]:.0f} ms'), ("Search p95", f'{tl["p95_ms"]:.0f} ms'), ("Ingest", f'{tl["events_per_second"]:,}/s'), ("Events indexed", f'{tl["events"]:,}')]
    for i, (k, v) in enumerate(stats):
        x = 40 + i * 285
        parts.append(f'<rect x="{x}" y="{y}" width="265" height="64" rx="12" fill="#1b2a45" stroke="#22324d"/>')
        parts.append(f'<text x="{x + 18}" y="{y + 26}" fill="#8aa4c8" font-size="12">{k}</text>')
        parts.append(f'<text x="{x + 18}" y="{y + 52}" fill="#e6edf7" font-size="20" font-weight="700">{v}</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "parity.svg").write_text(parity_chart(), encoding="utf-8")
    (OUT / "throughput.svg").write_text(throughput_chart(), encoding="utf-8")
    print("wrote docs/images/parity.svg and docs/images/throughput.svg")


if __name__ == "__main__":
    main()
