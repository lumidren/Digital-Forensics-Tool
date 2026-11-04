# Changelog

All notable changes are listed here. The format follows Keep a Changelog; versions follow SemVer.

## [0.1.0] - 2026-11-04

First complete release.

### Evidence integrity and custody
- Single-pass MD5, SHA-256 and SHA3-256 hashing at acquisition.
- Ed25519-signed, hash-chained custody ledger with key registry, validity windows, revocation and
  external anchors; Python writer wire-compatible with the Rust ledger.
- `veritas-verify`: independent PASS/FAIL verifier for raw ledgers and signed custody exports.
- Content-addressed write-once evidence store (local and S3 Object Lock) with per-case
  XChaCha20-Poly1305 encryption; multi-segment E01 evidence with per-segment hashes.

### Acquisition
- `veritas-agent`: live triage bundles, raw NTFS metadata copies, E01/raw imaging with bad-sector
  maps and resume (raw), write-block verification, WinPmem/LiME/osxpmem drivers, resumable mTLS upload,
  signed acquisition entries with an SNTP clock measurement.
- `veritas-ewf`: EnCase 6 E01 writer and reader, byte-identical media and equal hashes to libewf.

### Parsing
- File systems: NTFS, FAT/exFAT, ext2/3/4, APFS, VSS, MBR/GPT, carving, deleted-file recovery,
  BitLocker/LUKS/APFS decryption, E01 input, artifact harvest for Windows 10/11 and XP/2003, Linux and macOS.
- Windows, Linux, macOS, memory, network, malware, cloud and mobile artifact parsers (see docs/PARSERS.md).
- Parity harness against reference tools: 68 parsers, 99.41% field agreement; CI regression gate.

### Analysis and casework
- Unified Plaso-compatible timeline in SQLite FTS5 or ClickHouse, with timezone and clock-skew correction.
- Rules for timestomping (graded by evidence strength), anti-forensics, execution correlation with
  offensive-tool families, lateral movement, persistence, user activity, file provenance and IOC sweeps.
- Findings are proposals until an examiner confirms and a different reviewer approves them.
- RBAC, bookmarks, notes, hypotheses, tasks, saved views, PII masking, hash-chained audit log.

### Reporting
- Deterministic, signed PDF and DOCX reports from YAML templates; STIX 2.1, CSV, JSON Lines and Plaso exports.

### Platform
- FastAPI service, sandboxed parser workers, resumable job DAGs with atomic leased claims.
- Examiner web application (Next.js 15) with Playwright and axe end-to-end tests.
- Helm chart, Kubernetes manifests, Terraform for AWS, GitHub Actions CI/CD with signing and SBOM,
  Grafana dashboards, Prometheus alerts, backup and verified restore, DR drill.

### Fixed during hardening
- Journald parser overflow on hostile entry-array offsets (found by cargo-fuzz).
- Worker crash on non-ASCII parser output; harvest manifest paths; never-written `$LogFile`.
- Two workers could claim the same job; stale finding proposals accumulated on re-runs.
- Bearer tokens could appear in WebSocket access logs.
