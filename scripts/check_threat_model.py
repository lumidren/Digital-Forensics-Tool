#!/usr/bin/env python3
"""Verify that every mitigation in docs/THREAT_MODEL.md points at real code.

Each table row of the form `| T1.1 | ... | path/to/file |` must reference a file that exists
and contains the marker `THREAT:T1.1`. With `--update` the script rewrites the Location column
as `path:line` so that the document always carries current line numbers.

Exit status 0 when every reference resolves, 1 otherwise. Used as a CI gate.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "THREAT_MODEL.md"
ROW = re.compile(r"^\| (T\d+\.\d+) \| (.+?) \| ([^|]+?) \|\s*$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true", help="rewrite line numbers")
    args = parser.parse_args()

    lines = DOC.read_text(encoding="utf-8").splitlines()
    failures: list[str] = []
    out: list[str] = []
    checked = 0
    for line in lines:
        m = ROW.match(line)
        if not m:
            out.append(line)
            continue
        tid, mitigation, location = m.group(1), m.group(2), m.group(3).strip()
        path_part = location.split(":")[0]
        target = ROOT / path_part
        checked += 1
        if not target.exists():
            failures.append(f"{tid}: {path_part} does not exist")
            out.append(line)
            continue
        marker = f"THREAT:{tid}"
        found_line = None
        try:
            for i, text in enumerate(target.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if marker in text:
                    found_line = i
                    break
        except OSError as exc:  # pragma: no cover - unreadable file
            failures.append(f"{tid}: cannot read {path_part}: {exc}")
        if found_line is None:
            failures.append(f"{tid}: marker {marker} not found in {path_part}")
            out.append(line)
            continue
        out.append(f"| {tid} | {mitigation} | {path_part}:{found_line} |")

    if args.update and not failures:
        DOC.write_text("\n".join(out) + "\n", encoding="utf-8")
    for f in failures:
        print("FAIL", f)
    print(f"checked {checked} mitigations, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
