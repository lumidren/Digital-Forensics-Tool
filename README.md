# Veritas DFIR

Veritas is a digital forensics and incident response platform. It acquires evidence with
verifiable hashes, parses disk, memory, mobile, cloud and network artifacts, builds one timeline
across all of them, proposes findings for an examiner to confirm, and produces signed, reproducible
reports. Every access to evidence is recorded in an Ed25519-signed, hash-chained custody ledger that
an independent verifier re-checks from scratch.

| | |
|---|---|
| Parsers | 68 parsers checked field by field against The Sleuth Kit, libyal, Plaso, dissect, scapy and LIEF: **99.41% agreement over 1.48 million comparisons** ([PARITY.md](docs/PARITY.md)) |
| Real image | NIST CFReDS *Hacking Case* (4.87 GB) processed end to end in 134 s on one worker, reconstructing the intruder's toolkit ([BENCHMARKS.md](docs/BENCHMARKS.md)) |
| Custody | Signed hash chain, external anchors, `veritas-verify` prints PASS or FAIL with no access to the platform |
| Robustness | Safe Rust parsers, 14 cargo-fuzz targets, sandboxed parser workers with memory/time caps and no network |
| Reports | PDF and DOCX, byte-identical when regenerated from the same case state, hashed and signed |

## Quickstart (native, about 5 minutes plus build time)

No containers are needed. Requirements: Python 3.12 (64-bit), Rust 1.80+, Node 20+ for the web UI.

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap\quickstart.ps1 -Intrusion
```

Linux or macOS:

```bash
scripts/bootstrap/quickstart.sh --intrusion
```

The script:

1. creates `.venv` and installs the Python package;
2. builds the Rust tools (`cargo build --release --locked`);
3. starts the API on `http://127.0.0.1:8000` with data in `./var`;
4. downloads public reference data and, with `--intrusion`, the NIST *Hacking Case* laptop image
   (1.1 GB), refusing to continue if any SHA-256 differs from the pinned value;
5. creates users, a case, ingests everything, waits for processing, prints the proposed findings,
   generates a signed report, exports the custody ledger and runs `veritas-verify` on it.

It ends with:

```text
[8/8] custody
  veritas-verify: entries checked:    263
  veritas-verify: signatures checked: 264
  veritas-verify: PASS
```

Then start the examiner UI and open the printed case URL:

```bash
cd web && npm ci && npm run build && npm start
```

The timeline shows the reconstructed intrusion on the *Hacking Case* laptop. These findings are
proposed by the rules; an examiner must confirm each one, and a different reviewer must approve it:

```text
[high]   Dual-use tool observed: cain         (prefetch + ShimCache + UserAssist; execution proven)
[high]   Dual-use tool observed: ethereal     (packet capture, T1040)
[high]   Dual-use tool observed: netstumbler  (wireless discovery)
[high]   Dual-use tool observed: lookatlan    (network service discovery, T1046)
[medium] Dual-use tool observed: anonymizer   (proxy, T1090)
```

Without `--intrusion` the quickstart uses only small public test artifacts and finishes in about a
minute after the build. Credentials for the generated users are written to `var/bootstrap/credentials.json`.

## Verify a custody export yourself

```bash
target/release/veritas-verify export var/bootstrap/<case>-custody.json
```

The verifier rebuilds every hash link, checks every Ed25519 signature against the key registry and
its validity windows, checks external anchors, and prints `PASS` or `FAIL` with the failing entries.
It shares no code with the platform except the canonical JSON rules.

## What is in the box

| Area | Components |
|---|---|
| Acquisition | `veritas-agent`: live triage bundles, raw NTFS copies of `$MFT`/`$LogFile`/`$UsnJrnl`, E01 imaging with triple hashing and bad-sector maps, write-block check, WinPmem/LiME/osxpmem, resumable mTLS upload |
| File systems | NTFS (MFT, ADS, `$I30` slack, USN, `$LogFile`, timestomp indicators), FAT/exFAT, ext2/3/4, APFS, VSS, MBR/GPT, carving, BitLocker/LUKS/APFS decryption, E01 and split raw |
| Windows | registry (with log replay and deleted cells), UserAssist, ShellBags, MRUs, USB, ShimCache, Amcache, BAM, services, autoruns, EVTX and EVT, prefetch (to Win11), LNK, jump lists, SRUM, tasks, browsers, PST, Office, Recycle Bin, PowerShell, Timeline, WMI |
| Linux and macOS | journald, syslog, auth, auditd, utmp, shell histories, cron, systemd, SSH, package logs; unified log exports, FSEvents, KnowledgeC, plists, quarantine, TCC, launch agents, ASL, BSM |
| Memory, network, malware | Volatility 3 with injection/hollowing/credential-access heuristics; pcap/pcapng flows, DNS, HTTP, TLS JA3, Zeek; PE/ELF/Mach-O with Authenticode, YARA, VirusTotal/MalwareBazaar, CAPE/Cuckoo |
| Cloud and mobile | CloudTrail, S3, ELB, Azure/Entra, Google Workspace, M365 UAL; iOS backups, Android ADB backups and pulls |
| Analysis | super-timeline (SQLite FTS5 or ClickHouse), timezone and skew correction, execution correlation, lateral movement graph, persistence inventory, file provenance, IOC sweeps, ATT&CK mapping |
| Casework | multi-examiner cases, RBAC (viewer, examiner, reviewer, lead, admin), bookmarks, notes, hypotheses, tasks, two-person findings review, PII masking, hash-chained audit log |
| Web UI | Next.js 15, keyboard-first, WCAG 2.2 AA, dark and light themes, Lighthouse 100 on the audited pages |
| Operations | Helm chart, rendered Kubernetes manifests, Terraform for AWS, GitHub Actions CI/CD with signing and SBOM, Grafana dashboards, Prometheus alerts, backup and verified restore |

## Repository layout

```text
crates/            Rust: hash, ledger + veritas-verify, store, ewf, agent, fs, artifacts, timeline, cli
python/veritas/    API, pipeline, parsers, memory, network, malware, cloud, mobile, analytics, reporting
web/               examiner web application
deploy/            container files, Helm chart, Kubernetes manifests, Terraform, observability
scripts/           bootstrap, backup/restore, parity report and gate, determinism, fuzzing, benchmarks
testdata/          manifest of the public reference corpus (fetched by testdata/fetch.py)
parity/            per-parser comparison results and the CI baseline
docs/              architecture, threat model, compliance, parsers, runbooks, paper
```

## Tests

```bash
python testdata/fetch.py                                   # public corpus, hash-verified
cargo test --workspace --locked
.venv/Scripts/python -m pytest python/tests --cov=veritas  # 91% line coverage
python scripts/parity_report.py && python scripts/parity_gate.py
python scripts/determinism_check.py
python scripts/fuzz_smoke.py --seconds 60
cd web && npm test && npx playwright test
```

Tests that need ClickHouse, MinIO with Object Lock or Postgres are marked `integration` and run in CI
against service containers.

## Documentation

* [Architecture](docs/ARCHITECTURE.md), [Threat model](docs/THREAT_MODEL.md), [Standards alignment](docs/COMPLIANCE_MATRIX.md)
* [Parsers](docs/PARSERS.md), [Parity results](docs/PARITY.md), [Benchmarks](docs/BENCHMARKS.md), [Mobile scope](docs/MOBILE_SCOPE.md)
* [Examiner guide](docs/EXAMINER_GUIDE.md), [Runbook](docs/RUNBOOK.md), [Disaster recovery](docs/DR.md), [Security policy](SECURITY.md)
* [Technical paper](docs/paper/veritas-dfir.md) ([PDF](docs/paper/veritas-dfir.pdf)), [Contributing](CONTRIBUTING.md), [Changelog](CHANGELOG.md)

## Known limitations

* A 500 GB image was not processed end to end on the development machine; the figure in
  BENCHMARKS.md is a model built from measured stages and one measured 4.87 GB run.
* The memory-forensics comparison against Volatility needs a memory image supplied through
  `VERITAS_MEM_IMAGE`; no public image is small enough for the test corpus.
* Linux and macOS acquisition collectors compile and are unit-tested but have not run on real hosts.
* Encrypted iOS/Android backups, tracev3 unified logs and `$LogFile` replay are out of scope.
* Container images, the Terraform plan and the deploy workflows are validated statically; building
  and applying them needs CI credentials and AWS.

## License

Apache-2.0. Reference test data belongs to the Plaso, dfVFS and NIST CFReDS projects and is fetched,
not redistributed.
