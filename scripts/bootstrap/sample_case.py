#!/usr/bin/env python3
"""Build a sample Veritas case end to end against a running API (native profile, no containers).

Steps
  1. create the users ``admin``, ``examiner`` and ``reviewer`` through ``python -m veritas.api.manage``
     (same VERITAS_DATA_DIR / VERITAS_DATABASE_URL as the API);
  2. log in as the examiner, create a case and add the reviewer to it;
  3. obtain public reference artifacts listed in ``testdata/MANIFEST.json`` (Plaso test_data: EVTX,
     prefetch, registry hives), reusing ``testdata/corpus`` when present, and verify every SHA-256
     before anything is uploaded. ``--full`` adds a Digital Corpora disk image (see FULL_IMAGES);
  4. upload each file with ``expected_sha256`` so the API refuses a mismatch;
  5. wait for processing through ``/api/v1/cases/{id}/jobs``;
  6. run the findings rules and PRINT the proposed findings; nothing is confirmed automatically —
     confirming or rejecting a finding is an examiner decision taken in the web UI;
  7. generate a signed PDF report and verify its Ed25519 signature against the key registry;
  8. anchor the ledger, export the custody record and run the independent ``veritas-verify export``,
     printing PASS or FAIL.

Usage
  python scripts/bootstrap/sample_case.py [--api http://127.0.0.1:8000] [--full] [--out var/bootstrap]

Passwords: VERITAS_BOOTSTRAP_PASSWORD (>= 12 chars) for all three users, otherwise one random password
per user written to ``<out>/credentials.json`` with mode 0600. Passwords are never printed.
Exit status: 0 when the report signature and veritas-verify both PASS, non-zero otherwise.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parents[2]
RAW = {
    "plaso": "https://raw.githubusercontent.com/log2timeline/plaso/main/test_data/",
    "dfvfs": "https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/",
}
# Small, quick-to-process artifacts from the Plaso test corpus (Apache-2.0); hashes come from MANIFEST.json.
SAMPLES = [
    ("plaso", "evtx/System.evtx", "Windows System event log"),
    ("plaso", "winprefetch/CMD.EXE-087B4001.pf", "Prefetch: cmd.exe"),
    ("plaso", "winprefetch/PING.EXE-B29F6629.pf", "Prefetch: ping.exe"),
    ("plaso", "NTUSER.DAT", "User registry hive"),
    ("plaso", "SYSTEM", "SYSTEM registry hive"),
    ("plaso", "SOFTWARE", "SOFTWARE registry hive"),
]
# --full: a public disk image. Digital Corpora publishes the object (S3 ETag 372da6bdfe2b7f8eabb7a4d1924bd448-4,
# 29,678,014 bytes); the SHA-256 below was recorded from that object on 2026-11-04 and the EWF container also
# carries the acquisition MD5 of the media, which the pipeline re-checks when it opens the image.
FULL_IMAGES = [
    {
        "name": "nps-2009-canon2-gen1.E01",
        "url": "https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2009-canon2/nps-2009-canon2-gen1.E01",
        "sha256": "043d8014b646021fc9f6037155c6c7c44b8e918570d14f062606228f1c79c578",
        "size": 29678014,
        "description": "Digital Corpora nps-2009-canon2 (FAT camera card), generation 1, EWF",
        "kind": "disk",
    },
]
# --intrusion: NIST CFReDS "Hacking Case" (Dell Latitude CPi, user "Mr. Evil", wireless interception
# tools), a public intrusion image. NIST publishes the EnCase files without SHA-256 values; the hashes
# below were recorded from the NIST objects on 2026-11-04, and the E01 carries the acquisition MD5 of
# the 4,871,301,120-byte media (aee4fcd9301c03b3b054623ca261959a), which `ewf-tool verify` re-checks.
INTRUSION_SEGMENTS = [
    {"name": "4Dell Latitude CPi.E01", "url": "https://cfreds-archive.nist.gov/images/4Dell%20Latitude%20CPi.E01",
     "sha256": "96bebe80f00541bf28fbc2ef0b02b580082ee6ad58837e991852ae66f077ec31", "size": 671094597},
    {"name": "4Dell Latitude CPi.E02", "url": "https://cfreds-archive.nist.gov/images/4Dell%20Latitude%20CPi.E02",
     "sha256": "46bd09821dbb64675e5877d0ad7ec544a571fad5a3fd7fc3f0c3a16278887db5", "size": 419384951},
]
INTRUSION_MEDIA_MD5 = "aee4fcd9301c03b3b054623ca261959a"
USERS = [("admin", "Bootstrap Admin", True), ("examiner", "Sample Examiner", False), ("reviewer", "Sample Reviewer", False)]
TERMINAL = {"done", "failed", "skipped"}


def say(msg: str) -> None:
    print(msg, flush=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, dest: Path, expected_sha256: str, expected_size: int | None = None) -> Path:
    """Download (or reuse) ``dest`` and refuse to continue unless its SHA-256 matches."""
    if dest.exists() and sha256_file(dest) == expected_sha256:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    say(f"  downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as out:  # nosec B310 - fixed https URLs
        shutil.copyfileobj(r, out, 1 << 20)
    got = sha256_file(tmp)
    if got != expected_sha256 or (expected_size is not None and tmp.stat().st_size != expected_size):
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"FAIL hash mismatch for {url}: expected {expected_sha256}, got {got}; refusing to ingest")
    os.replace(tmp, dest)
    return dest


def resolve_samples(manifest_path: Path, corpus: Path, cache: Path, full: bool) -> list[dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))["files"]
    out = []
    for project, rel, desc in SAMPLES:
        expected = manifest[project][rel]
        local = corpus / project / rel
        if local.exists() and sha256_file(local) == expected:
            path = local
        else:
            path = fetch(RAW[project] + rel, cache / project / rel, expected)
        out.append({"path": path, "name": Path(rel).name, "sha256": expected, "description": f"{desc} (public reference: {project}/test_data/{rel})", "kind": "file"})
        say(f"  verified {project}/{rel} sha256={expected[:16]}...")
    if full:
        for img in FULL_IMAGES:
            path = fetch(img["url"], cache / "full" / img["name"], img["sha256"], img["size"])
            out.append({"path": path, "name": img["name"], "sha256": img["sha256"], "description": img["description"], "kind": img["kind"]})
            say(f"  verified {img['name']} sha256={img['sha256'][:16]}...")
    return out


def passwords(out: Path, reuse: bool) -> dict[str, str]:
    shared = os.environ.get("VERITAS_BOOTSTRAP_PASSWORD") or ""
    existing = out / "credentials.json"
    if reuse and not shared and existing.exists():
        return json.loads(existing.read_text(encoding="utf-8"))
    if shared and len(shared) < 12:
        raise SystemExit("VERITAS_BOOTSTRAP_PASSWORD must be at least 12 characters")
    creds = {uid: shared or secrets.token_urlsafe(18) for uid, _, _ in USERS}
    if not shared:
        out.mkdir(parents=True, exist_ok=True)
        path = out / "credentials.json"
        path.unlink(missing_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(creds, fh, indent=2)
        say(f"  generated passwords written to {path} (mode 0600)")
    return creds


def create_users(creds: dict[str, str]) -> None:
    for uid, name, is_admin in USERS:
        cmd = [sys.executable, "-m", "veritas.api.manage", "create-admin" if is_admin else "create-user", "--id", uid, "--name", name]
        env = {**os.environ, ("VERITAS_ADMIN_PASSWORD" if is_admin else "VERITAS_USER_PASSWORD"): creds[uid]}
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise SystemExit(f"FAIL creating user {uid}: {proc.stderr.strip()[-400:]}")
        say(f"  {proc.stdout.strip()}")


class Api:
    def __init__(self, base: str):
        self.c = httpx.Client(base_url=base.rstrip("/"), timeout=httpx.Timeout(600.0, connect=10.0))
        self.headers: dict[str, str] = {}

    def wait_ready(self, timeout_s: float) -> None:
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                if self.c.get("/readyz").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                raise SystemExit(f"FAIL API at {self.c.base_url} not ready after {timeout_s:.0f}s")
            time.sleep(1.0)

    def login(self, user: str, password: str) -> "Api":
        r = self.c.post("/api/v1/auth/login", json={"username": user, "password": password})
        self._ok(r, f"login {user}")
        other = Api.__new__(Api)
        other.c, other.headers = self.c, {"Authorization": f"Bearer {r.json()['access_token']}"}
        return other

    def _ok(self, r: httpx.Response, what: str) -> httpx.Response:
        if r.status_code >= 400:
            raise SystemExit(f"FAIL {what}: HTTP {r.status_code} {r.text[:400]}")
        return r

    def get(self, path: str, **kw) -> Any:
        return self._ok(self.c.get(path, headers=self.headers, **kw), f"GET {path}")

    def post(self, path: str, what: str | None = None, **kw) -> Any:
        return self._ok(self.c.post(path, headers=self.headers, **kw), what or f"POST {path}")


def wait_for_jobs(api: Api, case_id: str, expected: int, timeout_s: float) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout_s
    last = ""
    while True:
        jobs = api.get(f"/api/v1/cases/{case_id}/jobs").json()
        states = [j["state"] for j in jobs]
        line = f"  jobs: {len(jobs)}/{expected} " + " ".join(f"{s}={states.count(s)}" for s in sorted(set(states)))
        if line != last:
            say(line)
            last = line
        if len(jobs) >= expected and all(s in TERMINAL for s in states):
            return jobs
        if time.monotonic() > deadline:
            raise SystemExit(f"FAIL processing did not finish within {timeout_s:.0f}s")
        time.sleep(2.0)


def find_verifier() -> Path | None:
    exe = "veritas-verify" + (".exe" if os.name == "nt" else "")
    for d in filter(None, [os.environ.get("VERITAS_BIN_DIR"), str(REPO / "target" / "release")]):
        if (Path(d) / exe).is_file():
            return Path(d) / exe
    found = shutil.which("veritas-verify")
    return Path(found) if found else None


def verify_report_signature(sig: dict[str, Any], document: bytes, registry: dict[str, Any]) -> bool:
    from nacl.signing import VerifyKey

    if hashlib.sha256(document).hexdigest() != sig["report_sha256"]:
        return False
    rec = next((k for k in registry.get("keys", []) if k["key_id"] == sig["signer_key_id"]), None)
    if rec is None or rec["public_key"] != sig["signer_public_key"]:
        return False
    try:
        VerifyKey(bytes.fromhex(rec["public_key"])).verify(bytes.fromhex(sig["report_sha256"]), bytes.fromhex(sig["signature_ed25519"]))
        return True
    except Exception:
        return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Create a sample Veritas case from public reference data")
    ap.add_argument("--api", default=os.environ.get("VERITAS_API_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--web-url", default=os.environ.get("VERITAS_WEB_URL", "http://localhost:3000"))
    ap.add_argument("--manifest", default=str(REPO / "testdata" / "MANIFEST.json"))
    ap.add_argument("--corpus", default=str(REPO / "testdata" / "corpus"))
    ap.add_argument("--cache", default=str(REPO / "var" / "bootstrap-cache"))
    ap.add_argument("--out", default=os.environ.get("VERITAS_BOOTSTRAP_OUT", str(REPO / "var" / "bootstrap")))
    ap.add_argument("--full", action="store_true", help="also ingest a public Digital Corpora disk image")
    ap.add_argument("--intrusion", action="store_true", help="ingest the NIST CFReDS Hacking Case image (1.1 GB download) and reconstruct the intrusion")
    ap.add_argument("--skip-users", action="store_true", help="users already exist; passwords from VERITAS_BOOTSTRAP_PASSWORD or <out>/credentials.json")
    ap.add_argument("--timeout", type=float, default=1800.0, help="seconds to wait for processing")
    args = ap.parse_args(argv)
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    say("[1/8] users")
    creds = passwords(out, args.skip_users)
    if not args.skip_users:
        create_users(creds)
    api = Api(args.api)
    api.wait_ready(120)
    examiner = api.login("examiner", creds["examiner"])

    say("[2/8] case")
    case = examiner.post("/api/v1/cases", json={"name": "Sample case: public reference artifacts", "description": "Built by scripts/bootstrap/sample_case.py from the Plaso public test corpus.", "timezone": "UTC"}).json()
    case_id = case["id"]
    examiner.post(f"/api/v1/cases/{case_id}/members", json={"user_id": "reviewer", "role": "reviewer"})
    say(f"  case {case_id} created; examiner=lead, reviewer=reviewer")

    say("[3/8] reference data (sha256 verified before ingest)")
    samples = resolve_samples(Path(args.manifest), Path(args.corpus), Path(args.cache), args.full)

    say("[4/8] upload")
    for s in samples:
        with open(s["path"], "rb") as fh:
            r = examiner.post(f"/api/v1/cases/{case_id}/evidence", f"upload {s['name']}", files={"file": (s["name"], fh, "application/octet-stream")},
                              data={"kind": s["kind"], "description": s["description"], "host": "reference-host", "acquired_by": "public corpus", "tz_name": "UTC", "expected_sha256": s["sha256"]})
        ev = r.json()
        say(f"  {ev['id']} {s['name']:<32} sha256={ev['sha256'][:16]}... classified={ev['classified_as']} job={ev['job_id']}")

    expected_jobs = len(samples)
    if args.intrusion:
        say("  intrusion image: NIST CFReDS Hacking Case (two EWF segments, 1.1 GB)")
        segs = [fetch(sg["url"], Path(args.cache) / "hacking-case" / sg["name"], sg["sha256"], sg["size"]) for sg in INTRUSION_SEGMENTS]
        say(f"  verified segment hashes; media MD5 recorded by the acquirer: {INTRUSION_MEDIA_MD5}")
        r = examiner.post(f"/api/v1/cases/{case_id}/evidence/register-path", "register Hacking Case image",
                          json={"path": str(segs[0].resolve()), "kind": "disk", "name": segs[0].name, "expected_sha256": INTRUSION_SEGMENTS[0]["sha256"],
                                "description": "NIST CFReDS Hacking Case: Dell Latitude CPi laptop (public test image)", "host": "N-1A9ODN6ZXK4LQ",
                                "acquired_by": "NIST CFReDS", "tz_name": "America/Chicago"})
        ev = r.json()
        say(f"  {ev['id']} {ev['name']} sha256={ev['sha256'][:16]}... segments={1 + len(ev.get('segments', []))} job={ev['job_id']}")
        expected_jobs += 1

    say("[5/8] processing")
    jobs = wait_for_jobs(examiner, case_id, expected_jobs, args.timeout)
    for j in jobs:
        failed = [st["name"] for st in j.get("steps", []) if st["state"] == "failed"]
        say(f"  {j['job_id']} {j['kind']:<14} {j['state']}" + (f" failed steps: {failed}" if failed else ""))

    say("[6/8] findings (proposed only; nothing is confirmed automatically)")
    n = examiner.post(f"/api/v1/cases/{case_id}/findings/run").json()["proposed"]
    proposed = examiner.get(f"/api/v1/cases/{case_id}/findings", params={"state": "proposed"}).json()
    say(f"  rules proposed {n} finding(s); {len(proposed)} awaiting examiner review:")
    for f in proposed:
        say(f"   - [{f['severity']:<8}] {f['title']} (confidence {f['confidence']:.2f}, rule {f['rule']}, {len(f.get('event_ids', []))} events)")
    say(f"  ACTION: the examiner reviews each proposed finding in the web UI ({args.web_url}/cases/{case_id}) and confirms or rejects it;")
    say("          the reviewer then approves confirmed findings. Only approved findings appear in reports.")

    say("[7/8] signed report")
    rep = examiner.post(f"/api/v1/cases/{case_id}/reports", json={"format": "pdf", "limitations": ["Sample case built from public reference test data; no findings were approved at generation time."]}).json()
    doc = examiner.get(f"/api/v1/cases/{case_id}/reports/{rep['id']}/download", params={"part": "document"}).content
    sig = examiner.get(f"/api/v1/cases/{case_id}/reports/{rep['id']}/download", params={"part": "signature"}).json()
    report_path = out / f"{case_id}-{rep['id']}.pdf"
    report_path.write_bytes(doc)
    (out / f"{case_id}-{rep['id']}.sig.json").write_text(json.dumps(sig, indent=2, sort_keys=True), encoding="utf-8")
    registry = examiner.get("/api/v1/admin/keys").json()
    sig_ok = verify_report_signature(sig, doc, registry)
    say(f"  report {rep['id']} sha256={rep['report_sha256'][:16]}... signer={sig['signer']} key={sig['signer_key_id'][:12]}... signature {'PASS' if sig_ok else 'FAIL'}")

    say("[8/8] custody")
    anchor = examiner.post(f"/api/v1/cases/{case_id}/custody/anchor").json()
    online = examiner.get(f"/api/v1/cases/{case_id}/custody/verify").json()
    say(f"  anchored seq {anchor['seq']} head={anchor['head_hash'][:16]}...; API verifier: {online['verdict']} ({online['entries']} entries)")
    export_path = out / f"{case_id}-custody.json"
    export_path.write_bytes(examiner.get(f"/api/v1/cases/{case_id}/custody/export").content)
    verifier = find_verifier()
    if verifier is None:
        say("  FAIL veritas-verify not found; build it with: cargo build --release --locked -p veritas-ledger")
        return 3
    proc = subprocess.run([str(verifier), "export", str(export_path)], capture_output=True, text=True, check=False)
    for line in proc.stdout.strip().splitlines():
        say(f"  veritas-verify: {line}")
    verdict = "PASS" if proc.returncode == 0 and sig_ok and online["verdict"] == "PASS" else "FAIL"
    say("")
    say(f"case:            {case_id}")
    say(f"custody export:  {export_path}")
    say(f"report:          {report_path}")
    say(f"web UI:          {args.web_url}/cases/{case_id}")
    say(f"veritas-verify export: {'PASS' if proc.returncode == 0 else 'FAIL'}")
    say(verdict)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
