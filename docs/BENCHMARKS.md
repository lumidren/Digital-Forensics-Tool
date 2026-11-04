# Benchmarks

Measured 2026-11-04 on 12th Gen Intel(R) Core(TM) i7-12700H, 16 GB RAM, NVMe SSD, Windows 11. Release builds, single process unless noted.
Reproduce with `python scripts/benchmark.py --disk-gib 2 --events 1000000` (the figures below); defaults are 8 GiB and 5 million events.

## 1. Acquisition and integrity

Synthetic 2 GiB disk: alternating 4 MiB zero and random blocks.

| Stage | Seconds | GB/h | Output |
|---|---|---|---|
| hash (MD5+SHA-256+SHA3-256, single pass) | 10.25 | 755 |  |
| E01 imaging (zlib fast) + hashing | 18.38 | 421 | 1.01 GiB |
| E01 verify (decompress + re-hash, fast) | 11.66 | 663 |  |
| E01 imaging (zlib best) + hashing | 30.96 | 250 | 1.00 GiB |
| E01 verify (decompress + re-hash, best) | 11.78 | 656 |  |

## 2. Parser throughput (reference corpus, median of 3)

| Input | Size | Operation | MB/s | Events |
|---|---|---|---|---|
| System.evtx | 2,166,784 | hash (md5+sha256+sha3) | 219.5 |  |
| System.evtx | 2,166,784 | parse evtx | 13.3 | 5009 |
| MFT | 13,402,112 | hash (md5+sha256+sha3) | 235.9 |  |
| MFT | 13,402,112 | parse mft | 11.9 | 126276 |
| SYSTEM | 15,990,784 | hash (md5+sha256+sha3) | 206.0 |  |
| SYSTEM | 15,990,784 | parse registry | 53.6 | 31587 |
| SOFTWARE | 37,748,736 | hash (md5+sha256+sha3) | 178.6 |  |
| SOFTWARE | 37,748,736 | parse registry | 37.1 | 117932 |
| NTUSER.DAT | 786,432 | hash (md5+sha256+sha3) | 183.0 |  |
| NTUSER.DAT | 786,432 | parse registry | 31.0 | 1168 |
| ntfs.raw | 4,194,304 | hash (md5+sha256+sha3) | 199.8 |  |
| ntfs.raw | 4,194,304 | parse fs | 118.3 | 204 |
| ext4.raw | 4,194,304 | hash (md5+sha256+sha3) | 179.2 |  |
| ext4.raw | 4,194,304 | parse fs | 123.4 | 24 |
| CMD.EXE-087B4001.pf | 11,986 | hash (md5+sha256+sha3) | 14.9 |  |
| CMD.EXE-087B4001.pf | 11,986 | parse prefetch | 0.9 | 1 |

Parser throughput on small samples is dominated by process start-up; MB/s understates sustained rates.
The most relevant figure for large disks is MFT parsing: 111,913 file-system events per second.

## 3. Timeline store (SQLite + FTS5, native profile)

| Events | Ingest | Events/s | DB size | Queries | p50 | p95 | p99 | max | Full-range daily histogram |
|---|---|---|---|---|---|---|---|---|---|
| 1,000,000 | 35.5 s | 28,154 | 0.9 GiB | 240 | 65.5 ms | 242.3 ms | 660.8 ms | 752.5 ms | 336.0 ms |

Query mix: single-term full-text within a 7-day window, two-term full-text over all time, data type + host within 30 days, attribute equality within 3 days; limit 200, with exact total counts.
Tens of millions of events per case are served by the ClickHouse backend in the cluster profile; the SQLite store is the single-workstation default.

## 4. 500 GB image: processing model

Not measured end to end on this machine (about 55 GB free). Processing time for a disk image is the sum of:

* **Integrity re-verification** of the stored object: sequential read and triple hash, measured 755 GB/h, so 500 GB takes about 40 min.
* **Acquisition to E01** (agent side, before upload): measured 421 GB/h, about 71 min; E01 verification 663 GB/h.
* **File-system timeline and harvest** scale with metadata, not with image size: a 500 GB Windows system volume typically has 0.5 to 2 million MFT records (8 to 16 events each).
  At the measured 111,913 events/s that is roughly 4 min for 2 million records.
* **Timeline ingest** of about 30 million events at 28,154 events/s: about 18 min (SQLite); ClickHouse ingests in parallel batches.
* **Artifact parsing** (registry, EVTX, prefetch, browser databases) is bounded by the number of harvested artifacts, typically a few GB in total, and runs in parallel worker processes.

Estimated wall-clock for a 500 GB image on one worker: **about 61 minutes plus artifact parsing**, with no manual steps: verify, fs_timeline, harvest and analytics are DAG steps that resume after interruption (leased job claims). Workers scale horizontally in the cluster profile.


## 5. Measured end to end: NIST CFReDS Hacking Case

A real 4.87 GB disk (4,871,301,120 bytes of media; two EWF segments, 1.09 GB on disk; acquisition
MD5 `aee4fcd9301c03b3b054623ca261959a`, re-verified) processed through the API on one worker, with
no manual steps, via `scripts/bootstrap/sample_case.py --intrusion`.

| Step | Seconds | Notes |
|---|---|---|
| Register and store (copy into the WORM store, triple hash, custody entries) | 9.5 | both segments |
| verify (re-hash every stored segment) | 7.6 | |
| fs_timeline (partition table, NTFS walk) | 35.7 | 225,980 file-system events |
| harvest (extract 126 artifacts, store each as a signed derived object, parse 119 in sandboxed workers) | 71.0 | registry, EVT, prefetch, LNK, IE history, Recycle Bin, `$LogFile` |
| analytics (all rules over the whole case) | 10.2 | 13 proposed findings |
| **Total** | **134** | **about 130 GB/h of media**, 382,643 timeline events |

Full-text search over the resulting case took 73 to 242 ms per query (8 queries, exact totals).
The custody export (every access, extraction and parse recorded) verified with `veritas-verify`.

The harvest step dominates and scales with the number of artifacts rather than the image size,
which is why the 500 GB model above adds artifact parsing separately.
