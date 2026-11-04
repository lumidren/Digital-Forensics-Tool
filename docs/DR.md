# Veritas — Backup and Disaster Recovery

This document sets the recovery objectives for the cluster profile, explains how each class of data is
protected, gives the restore procedures, and records the latest DR drill. Operational alert handling is
in `docs/RUNBOOK.md`.

## 1. Objectives

| Data | RPO | RTO | Mechanism |
|---|---|---|---|
| Evidence objects (S3 Object Lock) | **0** | 4 h | Written once to a COMPLIANCE-locked bucket; S3 replication with Replication Time Control into a locked bucket in the DR region (99.99 % of objects within 15 min, alarm at 15 min). Also protected by AWS Backup continuous backup. |
| Case database (RDS PostgreSQL 16) | **15 min** (≤ 5 min typical) | 4 h | Multi-AZ synchronous standby. Automated backups kept 35 days give point-in-time restore to any second; transaction logs ship to S3 every 5 minutes. Automated backups are also replicated to the DR region (14 days). An hourly `pg_dump` goes into the encrypted application backup. |
| Custody ledgers, anchors, key registry, audit log, job state (EFS data directory) | **anchor interval** (hourly backup, 1 h worst case) | 4 h | Hourly application backup (`scripts/backup/backup.py`), hourly AWS Backup recovery points of EFS, copies in the DR vault. Anchors are published outside the platform, so any ledger entry up to the last anchor can be proven even if every copy of the ledger were lost. |
| Timeline index (ClickHouse) | 24 h | 4 h (+ rebuild) | ClickHouse `BACKUP DATABASE` to the backup bucket on each application backup. It is a derived index: it can always be rebuilt from the evidence objects by reprocessing, so its RPO does not bound evidence loss. |
| Reports | 1 h | 4 h | Part of the application backup; each report is also recorded (hash and signature) as a `transform` entry in the custody ledger. |

### Why these numbers

* **Evidence RPO 0.** An object is acknowledged to the examiner only after S3 has committed it under a
  COMPLIANCE retention; from that moment no principal (root included) can delete or overwrite it, and
  replication carries a locked copy to the DR region. Losing the primary region therefore loses no
  acknowledged evidence; at worst, objects written in the last ~15 minutes reach the replica late.
* **Database RPO 15 min.** RDS PITR restores to any second up to the latest restorable time, which
  trails the present by about 5 minutes (log upload interval). 15 minutes leaves margin for a delayed log
  upload. A regional loss falls back to the replicated automated backups in the DR region, with the
  same 5-minute log granularity.
* **Ledger RPO = anchor interval.** A ledger is an append-only, signed hash chain. Anchors (head hash +
  sequence number) are written outside the ledger file, and the backup runs hourly with the anchor
  cadence, so the worst-case loss is entries since the last backup, and every entry up to the last
  anchor stays provable from the anchor record alone. Losing unanchored tail entries is detectable
  (the verifier reports the gap against the next anchor or against the case database); it is never silent.
* **RTO 4 h.** Measured components (section 5): rebuilding the platform from Terraform and Helm is
  about 60–90 minutes (EKS cluster and node groups dominate), an RDS point-in-time restore of a
  100 GB instance is 30–60 minutes, restoring and verifying the application backup is minutes, and
  re-pointing DNS is under 5 minutes. 4 hours covers the sum with a margin for human coordination and
  for re-running the custody verification on every case before the platform is reopened.

## 2. What is backed up, where

| Layer | Schedule | Destination | Encryption | Immutability |
|---|---|---|---|---|
| Application backup (`backup.py`): case DB dump, audit log, job state, ledgers, anchors, key registry, sealed examiner keys, reports, evidence **manifest** (hashes, not data) | hourly (`backup` CronJob) | `s3://veritas-<env>-backups-<account>/app/` + DR replica | Archive sealed to the recovery X25519 key (NaCl sealed box + XChaCha20-Poly1305 frames), then SSE-KMS | Object Lock COMPLIANCE 90 days |
| RDS continuous backup | continuous, 35 days | RDS + AWS Backup vault + DR region | KMS (rds key) | Vault Lock (compliance mode after 3 days) |
| EFS data directory | hourly (7 days), daily (35 days), monthly (1 year) | AWS Backup vault + DR vault | KMS (backup key) | Vault Lock |
| Evidence bucket | continuous | S3 replication + AWS Backup continuous | SSE-KMS per environment, plus per-case XChaCha20 envelope in the application | Object Lock COMPLIANCE (default 10 years in prod) |
| ClickHouse | with each application backup | backup bucket `clickhouse/` | SSE-KMS | Object Lock |

The master key (`VERITAS_MASTER_KEY`, from which every per-case data key and the examiner key vault key
are derived) is **not** in the application backup by default. It lives in Secrets Manager (KMS
`secrets` key, multi-person access) and is escrowed offline as a sealed paper/HSM copy held by two key
custodians. The recovery X25519 private key is stored the same way. Without both, a backup archive is
useless to an attacker and to us.

## 3. Restore procedures

### 3.1 Single case database corruption or operator error (region healthy)

1. Freeze writes: `kubectl -n veritas scale deploy/veritas-api deploy/veritas-worker --replicas=0`.
2. Restore RDS to a point in time just before the incident into a new instance:
   `aws rds restore-db-instance-to-point-in-time --source-db-instance-identifier veritas-prod --target-db-instance-identifier veritas-prod-pitr --restore-time <UTC> --db-subnet-group-name veritas-prod --vpc-security-group-ids <db-sg> --multi-az`
3. Update `VERITAS_DATABASE_URL` in the `veritas/prod/runtime` secret to the new endpoint; wait for
   External Secrets to refresh (or annotate the ExternalSecret to force it).
4. Scale API and workers back up, then run the custody verification for every case
   (`kubectl -n veritas create job --from=cronjob/veritas-custody-verify verify-now`) and compare the
   case list with the ledger directory: every ledger must have its case row and vice versa.

### 3.2 Loss of the data directory (EFS) or ledger tampering suspected

1. Freeze writes as above.
2. Fetch the latest archive from the backup bucket and its `.sha256` sidecar.
3. Restore into a fresh directory and verify everything (Python and Rust verifiers, audit chain, store):

   ```bash
   python scripts/backup/restore.py veritas-backup-<stamp>.vbk --identity /secure/recovery.key \
       --target /restore/veritas --s3-bucket veritas-prod-evidence-<account> --deep --require-rust
   ```

   The command exits non-zero on any mismatch and writes `restore-report.json`. Do not proceed on FAIL:
   compare against the previous archive and the external anchors to bound the damage.
4. Copy the verified directory onto a new EFS access point (or restore the EFS recovery point from AWS
   Backup and diff it against the verified archive), point the PVC at it, scale up.

### 3.3 Regional disaster

1. Declare the incident; the evidence replica, the DR backup vault, the replicated RDS automated
   backups and the replicated backup archives are already in the DR region.
2. `terraform -chdir=deploy/terraform/aws/environments/prod apply -var region=<dr> -var dr_region=<primary> ...`
   with a DR state key, creating a fresh VPC/EKS/EFS/ALB in the DR region. Point `config.s3Bucket` at the
   **replica** bucket (it is Object-Locked with the same retention).
3. Restore RDS from the replicated automated backup to the latest restorable time
   (`aws rds restore-db-instance-to-point-in-time --source-db-instance-automated-backups-arn ...`).
4. Restore the latest application archive with `restore.py ... --s3-bucket <replica>` and load the data
   directory into the new EFS; run `RESTORE DATABASE veritas FROM S3(...)` for ClickHouse or reprocess.
5. Deploy the chart with `values-prod.yaml`, run the smoke test, run custody verification on every case,
   switch DNS (Route 53 alias) to the DR ALB.

### 3.4 Native profile (single machine)

```bash
python scripts/backup/backup.py keygen --out /secure/recovery          # once
python scripts/backup/backup.py create --recipient /secure/recovery.pub --out /backups
python scripts/backup/restore.py /backups/veritas-backup-<stamp>.vbk --identity /secure/recovery.key \
    --target /srv/veritas-restored --store-dir /mnt/worm/store --copy-store --deep --require-rust
```

The SQLite databases are copied with the online backup API, so the API can keep running during a backup.

## 4. Verification after any restore

A restore is complete only when all of these pass (all are run by `restore.py`):

* every archive frame authenticates, the `.sha256` sidecar matches, every file matches `MANIFEST.json`;
* every custody ledger verifies with the Python verifier **and** the independent Rust `veritas-verify`;
* every anchor's head hash matches the chain at its sequence number;
* the audit-log hash chain verifies; SQLite `integrity_check` is `ok`;
* every evidence object listed in the manifest exists in the (replica) store with the recorded stored
  checksum, and with `--deep` its plaintext MD5/SHA-256/SHA3-256 match the ingest hashes.

`python/tests/unit/test_backup_restore.py` exercises the PASS path and the FAIL paths (a modified ledger
line with and without a re-hashed manifest, a flipped ciphertext bit, a wrong recovery key, a truncated
archive, a replaced evidence object) on every CI run.

## 5. DR drill record

**Drill 2026-11-04, native profile, Windows 11 workstation (Python 3.12.16, veritas-verify built from
`crates/veritas-ledger` with `cargo build --release --locked`).**

Setup: API running natively (`uvicorn veritas.api.main:create_app`) on a fresh data directory;
`scripts/bootstrap/sample_case.py` created two cases (13 evidence uploads from the Plaso public test
corpus plus the Digital Corpora `nps-2009-canon2-gen1.E01` image, 29.7 MB), processed them, generated
signed reports and anchored both ledgers. Data directory 149 MB, evidence store 96 MB, 8 store objects.

Backup taken **while the API was running** (online SQLite backups):

```
{"archive_size": 1808990, "files": 19, "ledgers": 2, "ok": true, "store_objects": 8,
 "timings_s": {"case_db": 0.004, "timeline": 0.123, "audit_jobs": 0.006, "ledgers_keys_reports": 0.015,
               "store_manifest": 0.105, "archive_encrypt": 0.269, "total": 0.68}}
wall clock (process start to exit): 1.107 s
```

Restore into an empty directory with full verification
(`restore.py ... --store-dir <store> --copy-store --deep --require-rust`):

```
PASS  archive.sidecar_sha256                   veritas-backup-20261104T121204Z.vbk.sha256
PASS  archive.decrypt                          all frames authenticated
PASS  manifest.self_hash                       MANIFEST.json vs MANIFEST.sha256
PASS  manifest.file_hashes                     19 files; mismatched=[] missing=[] unlisted=[]
PASS  custody.python[C-20261104-6D7F3C]        16 entries
PASS  custody.anchors[C-20261104-6D7F3C]       1 anchors
PASS  custody.rust[C-20261104-6D7F3C]          PASS
PASS  custody.python[C-20261104-B0628F]        13 entries
PASS  custody.anchors[C-20261104-B0628F]       1 anchors
PASS  custody.rust[C-20261104-B0628F]          PASS
PASS  audit.chain                              52 rows
PASS  sqlite.integrity[veritas.db]             ok
PASS  sqlite.integrity[timeline.db]            ok
PASS  sqlite.integrity[audit.db]               ok
PASS  sqlite.integrity[jobs.db]                ok
PASS  store.objects                            8 objects
PASS  store.deep                               plaintext MD5/SHA-256/SHA3-256 re-hashed
timings (s): decrypt_extract=0.130, manifest_place=0.119, custody_verify=0.087, audit_db_verify=0.094,
             store_verify=0.781, total=1.221
PASS
wall clock (process start to exit): 1.609 s
```

Negative drill (pytest, same machine): `test_restore_fails_on_tampered_ledger_line` 0.72 s — a single
edited `purpose` field in ledger line 3 is reported as `manifest.file_hashes FAIL` and
`custody.python FAIL`; with the manifest re-hashed by the attacker the manifest checks pass and the
ledger check still FAILs with `entry_hash mismatch`; the CLI exits 1. Full test file: 5 tests, 2.6 s.

**Not covered by this drill:** the cluster profile (RDS PITR, ClickHouse `BACKUP`, S3 replica restore,
regional failover). Those steps need an AWS account and are to be drilled quarterly in staging; record
the measured times here (RDS PITR duration, EKS rebuild duration, total time to smoke-test PASS).
