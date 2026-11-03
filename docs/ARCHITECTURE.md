# Veritas DFIR — Architecture

## 1. Design goals

1. **Evidence never changes.** Bytes are hashed before they move, addressed by hash where they
   rest, and every access is recorded in a signed, hash-chained ledger.
2. **Every conclusion is traceable.** A timeline event names the evidence object, the byte offset
   or record it came from, and the parser version that produced it.
3. **Parsers are validated, not trusted.** Each parser ships with a parity test against a
   reference implementation (libyal, The Sleuth Kit, Plaso, Volatility 3) on public test data.
4. **Hostile input is expected.** Parsers are safe Rust or sandboxed Python; malformed input fails
   a job, never the platform.
5. **Runs on a laptop, scales in a cluster.** The default profile is native, single machine,
   SQLite and local filesystem. The same code targets Postgres, MinIO/S3 and ClickHouse when
   configured. No container runtime is required for the quickstart.

## 2. C4 — Context

```
                 +---------------------+
   Examiner ---> |  Veritas Web (Next) | <--- Reviewer / Admin
                 +----------+----------+
                            | HTTPS, OIDC
                 +----------v----------+        +--------------------+
   Agent ------> |  Veritas API (Py)   | -----> | Evidence store     |
   (Rust, mTLS)  |  FastAPI            |        | FS or S3 ObjectLock|
                 +----------+----------+        +--------------------+
                            |
         +------------------+------------------+
         v                  v                  v
   +-----------+     +-------------+     +--------------+
   | Ledger    |     | Pipeline    |     | Timeline idx |
   | (Rust lib)|     | workers     |     | SQLite/CH    |
   +-----------+     +-------------+     +--------------+
                            |
                     Rust parser crates via `veritas` CLI (JSONL out)
```

External systems: OIDC identity provider, KMS, VirusTotal / MalwareBazaar (optional, pluggable),
sandbox (CAPE/Cuckoo, optional), Zeek and Volatility 3 (local executables).

## 3. C4 — Containers

| Container | Tech | Responsibility |
|---|---|---|
| `veritas-agent` | Rust binary | Live triage, memory capture orchestration, disk imaging to E01/raw with streaming hashes, resumable mTLS upload. |
| `veritas` CLI | Rust binary | Front door to every Rust parser; emits JSON Lines in the unified event schema. Used by workers and by examiners directly. |
| `veritas-verify` | Rust binary | Independent custody verifier. No dependencies on the platform. |
| API | Python 3.12, FastAPI | Cases, evidence intake, RBAC, findings workflow, report generation, WebSocket progress. |
| Workers | Python | Job DAG per evidence item; spawns parser subprocesses with resource caps; indexes events. |
| Timeline index | SQLite FTS5 (default) or ClickHouse | Sub-second search over millions of events with facets. |
| Case DB | SQLite (default) or Postgres | Cases, users, notes, bookmarks, findings, audit log. |
| Evidence store | Local FS (WORM via read-only bits + refusal to overwrite) or S3 Object Lock | Content-addressed blobs. |
| Web | Next.js 15, TypeScript strict, Tailwind, shadcn/ui | Examiner UI. |

## 4. C4 — Components (Rust workspace)

```
crates/
  veritas-hash       MultiHasher: MD5 + SHA-256 + SHA3-256 in one pass, chunked, resumable state
  veritas-ledger     Entry, canonical JSON, Ed25519 signing, chain verification, key registry,
                     anchoring; bin: veritas-verify
  veritas-store      ContentStore trait; LocalStore (WORM), S3Store; per-case key wrapping
  veritas-ewf        EWF/E01 writer and reader (segments, zlib chunks, hash sections)
  veritas-agent      triage collectors, imaging, write-blocker check, transfer client
  veritas-fs         MBR/GPT, NTFS (MFT, $I30, ADS, USN, $LogFile), FAT32/exFAT, ext4, APFS,
                     carving, VSS enumeration, decryption adapters
  veritas-artifacts  REGF, EVTX, prefetch, LNK, shell items, jump lists (OLECF), shimcache,
                     amcache, BAM, SRUM (ESE), scheduled tasks, services, journald, plist
  veritas-timeline   unified Event schema (Plaso-compatible fields plus provenance), tz/skew
  veritas-cli        `veritas` command: parse, image, hash, verify, timeline, bench
```

Python package `python/veritas/`:

```
  parsers/      sqlite-backed artifacts (browsers, iOS backup, KnowledgeC, quarantine), email
                (PST via libpff), Office metadata, cloud logs, PCAP via Zeek, journald fallback
  memory/       Volatility 3 driver, custom plugins, YARA over process memory
  malware/      YARA, PE/ELF/Mach-O static analysis, authenticode, hash lookup adapters, sandbox
  timeline/     store backends (sqlite, clickhouse), normalization, skew correction
  analytics/    timestomp, execution correlation, lateral movement, persistence, provenance,
                IOC sweep, ATT&CK mapping, findings proposals
  pipeline/     DAG, worker sandbox, progress, idempotent steps
  api/          FastAPI routes, auth, RBAC, websockets
  reporting/    deterministic PDF/DOCX builder, STIX export
  audit/, pii/  hash-chained audit log, redaction
  parity/       harness comparing our output to reference tools; writes PARITY.md
```

## 5. Processing pipeline

```
intake ─┬─ hash+store ─ ledger(Acquire) ─ ledger(Ingest)
        └─ classify (magic, extension)
             ├─ disk image ─ partitions ─ filesystems ─┬─ file listing (MFT/inodes) ─ timestomp
             │                                          ├─ artifact harvest (known paths)
             │                                          ├─ USN / $LogFile / journal
             │                                          ├─ carving on unallocated
             │                                          └─ VSS snapshots ─ (recurse)
             ├─ memory image ─ volatility ─ yara
             ├─ triage bundle ─ per-artifact parsers
             ├─ pcap ─ zeek ─ flows/dns/http/tls/files
             ├─ cloud logs ─ normalizers
             └─ mobile backup ─ manifest ─ app databases
       all leaves ─► normalize(Event) ─► index ─► analytics ─► proposed findings
```

Each box is an idempotent step keyed by `(evidence_sha256, step, parser_version)`. A rerun with
identical inputs reuses the stored output hash and skips work. Progress is reported per step
over WebSocket. Priority queues: triage bundles before full images; memory before disk.

Measured throughput on the reference images is recorded in `docs/BENCHMARKS.md`.

## 6. Unified event schema

Plaso-compatible core fields plus provenance:

| Field | Type | Notes |
|---|---|---|
| `timestamp` | int64 ns since epoch, UTC | Always UTC; original tz kept in `timezone`. |
| `timestamp_desc` | string | Plaso vocabulary: Creation Time, Last Access Time, Content Modification Time, Metadata Modification Time, Last Login Time ... |
| `data_type` | string | Plaso data type name where one exists, e.g. `fs:stat:ntfs`, `windows:evtx:record`, `windows:prefetch:execution`. |
| `message` | string | Human readable, deterministic. |
| `source_short`, `source_long` | string | Plaso style. |
| `evidence_sha256` | string | Object the event came from. |
| `evidence_path` | string | Path inside the image, or artifact path in a triage bundle. |
| `offset` | int64 | Byte offset or record number inside the artifact. |
| `parser`, `parser_version` | string | Provenance. |
| `host`, `user` | string | When derivable. |
| `skew_ns` | int64 | Applied clock correction. |
| `attrs` | object | Parser-specific fields (deterministic key order). |

## 7. Determinism rules

- No wall-clock reads inside parsers. Time comes from evidence.
- No hash maps in output paths; `BTreeMap` and sorted vectors only.
- Floats are forbidden in canonical JSON; durations and sizes are integers.
- Events are sorted by `(timestamp, data_type, evidence_path, offset)` before export.
- Report generation uses a fixed document creation date taken from the case state, embeds no
  random IDs and sets PDF `/ID` from the content hash.

## 8. Security architecture summary

See `docs/THREAT_MODEL.md` for the full table. Key points: hash-chained Ed25519 ledger with an
independent verifier; content-addressed WORM store; parser isolation; RBAC with reviewer
separation; hash-chained audit log; secrets never logged.

## 9. Deployment profiles

| Profile | Case DB | Timeline | Store | Queue |
|---|---|---|---|---|
| native (default) | SQLite | SQLite FTS5 | local FS | in-process |
| cluster | Postgres | ClickHouse | S3 Object Lock | Postgres-backed queue |

Container, Helm and Terraform definitions live under `deploy/` for the cluster profile. They are
not used by the quickstart.
