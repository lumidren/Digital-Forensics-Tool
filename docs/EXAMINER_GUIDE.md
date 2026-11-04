# Examiner Guide

This guide walks a case from acquisition to court. Every step leaves a signed entry in the case's
custody ledger; nothing you do in Veritas is silent.

## 1. Roles

| Role | Can |
|---|---|
| viewer | read the case, timeline (PII masked), findings, custody ledger |
| examiner | everything a viewer can, plus ingest evidence, view bytes, bookmark, note, confirm or reject findings, build reports |
| reviewer | everything an examiner can, plus approve or return findings confirmed by someone else |
| lead | everything, plus case membership, legal hold, evidence export, ledger anchoring |
| admin (global) | user management, key revocation, audit log, store verification; may unmask PII |

A finding is reported only after one examiner confirms it with a written rationale **and** a
different reviewer approves it. The platform enforces the separation; it is not a convention.

## 2. Acquire

On the subject system (or a forensic workstation with a write blocker):

```bash
veritas-agent keygen --out examiner-key.json
```

```bash
veritas-agent image --source \\.\PhysicalDrive1 --out D:\case42\laptop --format e01 --case 42 --evidence EV-1 --examiner "J. Doe" --ledger D:\case42\ledger.jsonl --key examiner-key.json
```

The agent checks write protection first and records the result, hashes the stream with MD5,
SHA-256 and SHA3-256 while writing the E01, zero-fills and maps unreadable sectors, measures the
clock offset against NTP, and appends a signed `acquire` entry. Live triage (volatile data, logs,
hives, `$MFT`/`$UsnJrnl`/`$LogFile`, browser databases) is `veritas-agent triage --out bundle.zip`.
Memory capture is `veritas-agent memory --tool winpmem --out mem.raw`.

Upload with `veritas-agent upload --server https://veritas.example --client-cert ... <image>.manifest.json`;
transfers resume segment by segment and every segment is checked against its hash.

## 3. Ingest

Web: **Case > Evidence > Add evidence** (drag and drop). Choose the kind (disk, memory, triage,
logs, pcap, cloud, mobile, file), paste the expected SHA-256 from your acquisition notes, and set
the host's timezone and measured clock skew if known. The upload is refused if the hash differs.

The object is stored write-once under its SHA-256, a signed `ingest` entry is written, and a
processing job starts. Its progress appears live on the processing queue. Disk images are walked
for a file-system timeline, then known artifacts are extracted (each extraction is a signed
`transform` entry) and parsed in sandboxed workers. Analytics run last and *propose* findings.

## 4. Examine

* **Timeline** (`g t`): full-text search, filters (time, type, host, user, evidence, parser,
  attribute), histogram brushing with the keyboard, pivots on any value, saved views. Press `b` to
  bookmark the selected event, `?` for every shortcut.
* **Event detail** shows provenance: evidence hash, path inside the evidence, record offset, parser
  version, and any clock correction applied.
* **Bytes**: the hex viewer reads evidence bytes directly; each view is a custody `access` entry.
* **Graphs**: lateral movement (who logged on where, how) and file provenance (download, attachment
  or archive origin, then execution, rename, deletion).
* **IOCs**: paste hashes, IPs, domains, URLs, paths or regexes; sweep the whole case; export STIX 2.1.
* **PII** is masked by default with stable tokens (the same value masks to the same token). Unmasking
  needs the permission and is audited.

## 5. Decide

Open **Findings** (`g f`). Each proposal lists the rule, the supporting events and an ATT&CK
mapping. Read the supporting artifacts, then **Confirm** or **Reject** with a rationale of at
least a sentence. Rules grade their own evidence; for example, timestamp anomalies inside
installation directories are summarised as low severity instead of being raised file by file,
because installers produce the same pattern as timestomping tools. Hypotheses track competing
explanations with supporting and refuting events; tasks assign follow-up work.

A reviewer then approves or returns each confirmed finding. You cannot approve your own.

## 6. Report

**Reports > Generate** (PDF or DOCX). The report contains the executive summary, scope,
methodology, tool versions and binary hashes, parser validation figures, evidence inventory with the
custody chain, approved findings with every supporting artifact (time, type, evidence hash, path,
offset and the ingest ledger entry), limitations and your attestation. The file is hashed, signed
with your Ed25519 key, and recorded as a `transform` ledger entry. Generating again from the same
case state produces a byte-identical document.

## 7. Prove custody

**Custody > Export** downloads a signed JSON export. Anyone can verify it without access to the
platform:

```bash
veritas-verify export case42-custody.json
```

The verifier rebuilds every hash link, checks every signature against the key registry and its
validity windows, checks anchors, and prints `PASS` or `FAIL` with the failing entries. Give the
export, the registry fingerprints printed in the report, and the verifier's source or signed binary
to opposing counsel's expert.

`veritas hash --media laptop.E01` recomputes the image hashes independently of the platform.

## 8. Testifying notes

* Tool versions, binary hashes and parser agreement rates are in the report's methodology section;
  per-field agreement is in `docs/PARITY.md`.
* Known limitations of each parser are in `docs/PARSERS.md`. ShimCache and Amcache prove presence,
  not execution; the execution view states which sources prove execution for each program.
* Every timestamp is UTC. Corrections for host timezone and clock skew are applied at ingest,
  recorded per event, and reversible.
