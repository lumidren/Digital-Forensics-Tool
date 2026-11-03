# Standards Alignment Matrix

Each row maps a requirement from a recognized standard or guideline to the control in Veritas
that satisfies it, and to the evidence (test, document or code) that shows the control works.

Legend for Status: **Implemented** (code and test exist), **Procedural** (documented practice
the examiner follows; the platform supports but cannot enforce), **Partial** (see note).

## ISO/IEC 27037:2012 — Identification, collection, acquisition and preservation of digital evidence

| Clause | Requirement | Control | Evidence | Status |
|---|---|---|---|---|
| 5.3.1 | Auditability: a third party must be able to evaluate the activities performed. | Signed hash-chained ledger; independent verifier. | `crates/veritas-ledger`, `veritas-verify` CLI, custody report | Implemented |
| 5.3.2 | Repeatability: same results with same procedures. | Determinism tests across runs. | `crates/*/tests/determinism.rs`, `python/tests/test_determinism.py` | Implemented |
| 5.3.3 | Reproducibility: same results with different instruments. | Parity harness against reference tools. | `docs/PARITY.md` | Implemented |
| 5.3.4 | Justifiability: choices are justified. | Methodology section auto-generated with tool versions and hashes. | `python/veritas/reporting` | Implemented |
| 5.4.2 | Documented chain of custody including identity, time, purpose for each handling. | Every ledger entry carries actor, time source, purpose. | `Entry` struct | Implemented |
| 6.2.1 | DEFR competence and authorization recorded. | Acquirer identity and key enrolment with role. | key registry | Implemented |
| 6.7 | Preserve integrity: use of write blockers, hashing. | Write-blocker verification before imaging; triple hash. | `crates/veritas-agent/src/writeblock.rs` | Implemented |
| 7.1.2 | Prioritize volatile data. | Triage order: memory, network, processes before disk. | `crates/veritas-agent/src/triage` | Implemented |
| 7.1.3 | Record system time and offset against a reference. | Trusted-time record in acquisition entry. | `TimeSource` in ledger | Implemented |

## NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response

| Section | Requirement | Control | Evidence | Status |
|---|---|---|---|---|
| 3.1.1 | Collection: identify and acquire data while preserving integrity. | Agent hashing, E01 with embedded hashes. | `crates/veritas-ewf` tests | Implemented |
| 3.1.2 | Maintain chain of custody with detailed log. | Ledger. | verifier | Implemented |
| 3.2 | Examination: use tools and techniques appropriate to the data; account for tool limitations. | Parser limitations documented; parity results published. | `docs/PARSERS.md` | Implemented |
| 3.3 | Analysis: correlate data from multiple sources. | Super-timeline, execution correlation, lateral movement. | `python/veritas/analytics` | Implemented |
| 3.4 | Reporting: audience-appropriate, with alternative explanations and limitations. | Report template includes executive summary, limitations, attestation. | `python/veritas/reporting/templates` | Implemented |
| 4.2.3 | Verify integrity of files with hashes before and after. | Store re-verification job. | `veritas verify-store` | Implemented |
| 5.2 | Collect OS data in order of volatility. | Triage ordering. | agent | Implemented |
| 6.3 | Network traffic: capture and analyze with timestamps synchronized. | Zeek integration and skew correction. | `python/veritas/parsers/pcap.py` | Implemented |

## SWGDE Best Practices for Computer Forensic Acquisitions (v1.0) and Digital Evidence Collection

| Item | Requirement | Control | Evidence | Status |
|---|---|---|---|---|
| 4.1 | Document the acquisition tool, version and settings. | Tool version, build hash and command line recorded in ledger. | `Entry.tool` | Implemented |
| 4.3 | Verify acquisition with hash values. | Hash computed during imaging and stored in E01 hash section and ledger. | tests | Implemented |
| 5.2 | Use of hardware or software write blockers verified. | Write-protect check before imaging (Windows: volume RO flag and disk attributes; Linux: blockdev RO). | `writeblock.rs` | Implemented |
| 6 | Error handling: unreadable sectors documented. | Bad-sector map recorded in image metadata and report. | `crates/veritas-agent/src/image.rs` | Implemented |
| 7 | Image format: self-describing with metadata. | E01 header sections with case, examiner, notes. | `veritas-ewf` | Implemented |

## ACPO Good Practice Guide for Digital Evidence — Four Principles

| Principle | Requirement | Control | Evidence | Status |
|---|---|---|---|---|
| 1 | No action should change data that may later be relied upon. | Write-blocker check; read-only mounting; WORM store. | agent, store | Implemented |
| 2 | Where original data must be accessed, the person must be competent and able to explain implications. | Live-triage actions are recorded with the actor identity, tool hash and rationale field. | ledger `purpose` | Implemented |
| 3 | An audit trail of all processes must be created and preserved so a third party can reproduce the result. | Ledger plus pipeline step hashes plus deterministic parsers. | verifier, determinism tests | Implemented |
| 4 | The person in charge has overall responsibility for ensuring the law and these principles are adhered to. | Case lead role; findings approval workflow. | RBAC | Procedural |

## Additional: evidence-handling controls referenced by courts (Daubert / FRE 902(13)-(14))

| Requirement | Control | Status |
|---|---|---|
| Authentication by hash (FRE 902(14)). | Hashes in ledger and report; verifier. | Implemented |
| Tool error rates known and testable. | Parity table with field agreement rates; fuzz results. | Implemented |
| Standards and controls governing the technique. | This matrix and the methodology section. | Implemented |

## Gaps

- ACPO Principle 4 and ISO 27037 6.2.1 competence are procedural: the platform records who did
  what, but cannot verify training.
- Hardware write-blocker presence can only be inferred (device reports read-only); the agent
  records the inference and the examiner attests to the physical blocker in the report.
