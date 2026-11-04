#!/usr/bin/env python3
"""Fetch the public reference corpus used by parity and determinism tests.

Sources (all public, Apache-2.0):
  - log2timeline/plaso   test_data   (Windows, Linux, macOS artifacts)
  - log2timeline/dfvfs   test_data   (small NTFS, ext, FAT, APFS, VSS, BitLocker, LUKS images)

Files land in testdata/corpus/<project>/<path>. Each file is verified against
testdata/MANIFEST.json (sha256) after download; a mismatch is a hard failure so tests never
run on a corrupted or substituted corpus.

Usage:
  python testdata/fetch.py                # download everything in the manifest
  python testdata/fetch.py --from DIR     # copy from a local sparse checkout instead
  python testdata/fetch.py --verify       # only verify what is present
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import sys
import time
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
MANIFEST = HERE / "MANIFEST.json"
CORPUS = HERE / "corpus"
# Corpus paths that differ from their upstream location.
UPSTREAM = {
    ("plaso", "msiecf/MSHist012013031020130311-index.dat"): "MSHist012013031020130311-index.dat",
    ("plaso", "msiecf/WebCacheV01.dat"): "WebCacheV01.dat",
}
RAW = {
    "plaso": "https://raw.githubusercontent.com/log2timeline/plaso/main/test_data/",
    "dfvfs": "https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/",
}


def sha256_of(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="src", help="local directory holding plaso/ and dfvfs/ checkouts")
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()

    manifest = json.loads(MANIFEST.read_text())
    failures = 0
    for project, files in manifest["files"].items():
        for rel, expected in files.items():
            dest = CORPUS / project / rel
            if not dest.exists() and not args.verify:
                dest.parent.mkdir(parents=True, exist_ok=True)
                if args.src:
                    shutil.copyfile(pathlib.Path(args.src) / project / "test_data" / rel, dest)
                else:
                    remote = UPSTREAM.get((project, rel), rel)
                    remote = remote[:-1] + "TILDE" if remote.endswith("~") else remote  # upstream stores "x~" as "xTILDE"
                    url = RAW[project] + urllib.parse.quote(remote)  # names contain spaces, "$" and "@"
                    print("fetch", url)
                    for attempt in range(4):
                        try:
                            with urllib.request.urlopen(url, timeout=120) as r, dest.open("wb") as fh:  # noqa: S310  # nosec B310 - fixed https base URLs
                                shutil.copyfileobj(r, fh)
                            break
                        except OSError as exc:
                            if attempt == 3:
                                raise
                            print(f"  retry after {exc}")
                            time.sleep(2 ** attempt)
            if not dest.exists():
                print("MISSING", project, rel)
                failures += 1
                continue
            actual = sha256_of(dest)
            if actual != expected:
                print(f"HASH MISMATCH {project}/{rel}: expected {expected} got {actual}")
                failures += 1
    print(f"corpus check: {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
