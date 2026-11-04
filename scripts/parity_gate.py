#!/usr/bin/env python3
"""CI gate: a change may not reduce agreement with reference tools.

Compares every (parser, field) ratio in parity/results/*.json with parity/baseline.json.
Fails when a ratio drops, when a baseline field disappears, or when a baseline parser has no
result. ``--update`` rewrites the baseline from current results (used deliberately in a PR that
explains why).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = ROOT / "parity" / "results"
BASELINE = ROOT / "parity" / "baseline.json"
EPS = 1e-9


def current() -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    for p in sorted(RESULTS.glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        out[d.get("parser", p.stem)] = {k: (f["agree"] / f["total"] if f["total"] else 1.0) for k, f in d.get("fields", {}).items()}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--update", action="store_true")
    args = ap.parse_args()
    cur = current()
    if args.update:
        BASELINE.write_text(json.dumps({p: {k: round(v, 6) for k, v in sorted(f.items())} for p, f in sorted(cur.items())}, indent=1) + "\n", encoding="utf-8")
        print(f"baseline updated: {len(cur)} parsers")
        return 0
    if not BASELINE.exists():
        print("no baseline; run with --update first", file=sys.stderr)
        return 1
    base = json.loads(BASELINE.read_text(encoding="utf-8"))
    failures: list[str] = []
    for parser, fields in sorted(base.items()):
        if parser not in cur:
            failures.append(f"{parser}: no parity result produced")
            continue
        for field, ratio in sorted(fields.items()):
            now = cur[parser].get(field)
            if now is None:
                failures.append(f"{parser}.{field}: field no longer compared")
            elif now + EPS < ratio:
                failures.append(f"{parser}.{field}: agreement dropped {ratio:.4%} -> {now:.4%}")
    for f in failures:
        print("PARITY REGRESSION", f)
    improved = sum(1 for p, fs in cur.items() for k, v in fs.items() if v > base.get(p, {}).get(k, 2.0) + EPS)
    print(f"parity gate: {len(failures)} regressions, {improved} improvements")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
