# Veritas — Operations Runbook

Cluster profile on EKS (Helm chart `deploy/helm/veritas`, infrastructure `deploy/terraform/aws`).
Namespace `veritas`, release `veritas`. Dashboards: `deploy/observability/grafana/*.json`. Alert rules:
`deploy/observability/prometheus/alerts.yml`. Backups and disaster recovery: `docs/DR.md`.

Golden rules: never delete or rewrite evidence, ledger lines or audit rows to "fix" anything; every
manual action on a case is recorded as a custody `note` entry through the API; when integrity is in
doubt, freeze the case first and investigate second.

```bash
aws eks update-kubeconfig --name veritas-prod --region eu-west-1
alias kv='kubectl -n veritas'
```

## 1. Alerts

### VeritasApiDown
No healthy API target for 5 minutes.
1. `kv get pods -l app.kubernetes.io/component=api` and `kv describe pod <pod>`; check events for
   image pull, OOMKilled, failed probes.
2. `kv logs deploy/veritas-api --since=15m` — JSON logs; secrets are scrubbed.
3. `/readyz` runs a database query: if it fails, check RDS (`aws rds describe-db-instances`) and the
   `veritas-runtime` Secret (`kv get externalsecret veritas-runtime -o yaml` → status `SecretSynced`).
4. If a release caused it: `helm -n veritas history veritas` then `helm -n veritas rollback veritas <rev> --wait`.

### VeritasQueueDepthHigh
More than 25 jobs pending/running for 30 minutes.
1. Grafana "Veritas / Processing": is throughput (GB/h) flat (stuck) or high (backlog)?
2. Stuck: `kv logs deploy/veritas-worker --since=30m`; look for a parser killed by the memory/CPU limits
   (`VERITAS_MEM_BYTES`, `VERITAS_CPU_S`), or an evidence item that times out repeatedly. Jobs are
   idempotent per `(evidence_sha256, step, parser_version)`; restarting a worker resumes safely:
   `kv rollout restart deploy/veritas-worker`.
3. Backlog: see "Scaling workers" (section 2).

### VeritasParserErrorRatioHigh
More than 5 % parser failures over 30 minutes.
1. Dashboard panel "Parser errors by step" shows which step fails.
2. A single malformed evidence item failing repeatedly is expected behaviour (hostile input fails the
   job, not the platform): mark it in the case notes. Many items failing in one parser after a release
   is a regression: roll back (section 1, VeritasApiDown step 4) and open an incident.
3. Compare with the parity results of the release (`parity/results`, CI artifact `parity-results`).

### VeritasSearchLatencyP95High
Timeline search p95 above 1 s.
1. ClickHouse health: `kubectl -n clickhouse get pods`, `system.merges`, `system.parts` count per partition,
   disk usage of the PVCs.
2. Very large cases: check `veritas_timeline_events` per case; long unbounded text queries without a
   time range are the usual cause — advise examiners to add a time range or facet.
3. Scale ClickHouse vertically (Terraform `module.clickhouse` resources) or add replicas.

### VeritasApi5xxRatioHigh
More than 2 % 5xx for 10 minutes. "Veritas / API (RED)": which routes? Correlate with deploys
(`helm history`), RDS/ClickHouse/S3 errors in API logs, and WAF/ALB alarms in CloudWatch. Roll back
if it started with a release.

### VeritasStoreGrowthAnomaly
The evidence store grew more than 4× its 7-day hourly average (and > 10 GB) in an hour. Usually a large
ingest: confirm with the case leads (audit log: `GET /api/v1/admin/audit?actor=...`). Unknown uploads
are a security event: identify the actor in the audit log, disable the account (section 4).

### VeritasStoreShrank
The object count of the WORM store decreased. This cannot happen through the application; S3 Object Lock
COMPLIANCE forbids deletion. Treat as an integrity incident: preserve CloudTrail and S3 access logs
(`s3://veritas-<env>-logs-<account>/s3/`), run `python -m veritas.api.manage verify-store` from an API
pod, compare the object list with the latest backup manifest (`restore.py` prints missing objects), and
escalate to security.

### VeritasCustodyVerifyFailed
A custody ledger failed hash-chain or signature verification.
1. Freeze the case: set it to `review` and stop processing (`PATCH /api/v1/cases/{id}` with `{"status": "review"}`).
2. Get the details: `kv logs job/<latest custody-verify job>`; then from an API pod
   `python -m veritas.api.manage verify-custody <case>` prints the failing sequence numbers.
3. Export the ledger and verify independently: `veritas-verify ledger <case>.jsonl --registry registry.json --anchors <case>.anchors.jsonl`.
4. Compare with the last backup archive (`restore.py` into a scratch directory) and with the external
   anchors to establish which entries changed and when. Do not edit the ledger. Record findings as a
   `note` entry and inform the case lead and counsel: the custody record must disclose the event.

### VeritasCustodyVerifyStale
No custody verification result in 8 hours: `kv get cronjob veritas-custody-verify`, `kv get jobs`,
check the Pushgateway is reachable (NetworkPolicy `veritas-ops` allows TCP 9091 to the monitoring namespace).
Run it now: `kv create job --from=cronjob/veritas-custody-verify verify-now`.

### VeritasBackupFailed
The hourly backup failed or none succeeded for 2 hours.
1. `kv logs job/<latest backup job>` — the job prints one JSON line with the error.
2. Common causes: `pg_dump` cannot reach RDS (password rotated: refresh the runtime secret), S3 upload
   denied (IRSA role `veritas-<env>-ops`), scratch volume full (`backup.scratchSizeLimit`), ClickHouse
   backup destination not allowed.
3. Re-run: `kv create job --from=cronjob/veritas-backup backup-now`. The ledger RPO (docs/DR.md) is
   exceeded while this alert fires; anchor active cases manually meanwhile (`POST /api/v1/cases/{id}/custody/anchor`).

### VeritasCertificateExpiringSoon / VeritasCertificateNotReady
`kv describe certificate veritas-prod-tls`, `kubectl describe clusterissuer letsencrypt-prod`,
`kubectl -n cert-manager logs deploy/cert-manager`. DNS-01/HTTP-01 challenges must reach the ingress.
The ALB listener uses a separate ACM certificate (auto-renewed by ACM with DNS validation in Route 53).

### CloudWatch alarms (SNS `veritas-<env>-alarms`)
RDS CPU/storage/memory, ALB 5xx, WAF blocked spike, EFS I/O limit, AWS Backup job and copy failures,
evidence replication latency/failures. The replication alarms map to the evidence RPO of 0: any
`OperationsFailedReplication` > 0 needs an S3 Batch Replication job for the failed objects.

## 2. Scaling workers

* The job queue lives in Postgres (`VERITAS_JOBS_URL`, set by the chart from the database secret).
  `JobStore.claim()` is an atomic compare-and-set with a 15-minute lease renewed on every progress
  report, so exactly one worker runs a job; if a worker dies, its lease expires and another worker
  resumes the job at its first incomplete step (`test_concurrent_claims_are_exclusive`). API pods set
  `VERITAS_INPROCESS_WORKER=0` and only enqueue.
* Vertical scaling: raise `worker.resources` and `worker.memoryBytesPerParser`; the worker node
  group (`worker_node_scaling` in Terraform) provides the capacity.
* Horizontal scaling: `worker.autoscaling.maxReplicas` (default 20). KEDA scales on
  `max(veritas_queue_depth)` with 4 jobs per replica, plus a CPU trigger; with KEDA disabled a plain CPU
  HPA is rendered instead. Scale-down is limited to one pod per 5 minutes and the pod has 15 minutes
  (`terminationGracePeriodSeconds`) to finish its step.

## 3. Rotating keys and secrets

| Secret | Rotation |
|---|---|
| KMS keys (evidence, rds, eks, logs, backup, efs, secrets) | Automatic yearly rotation (Terraform `enable_key_rotation`); old key material stays available for decryption. Nothing to do. |
| RDS master password | Managed by RDS in Secrets Manager (rotation schedule in the RDS console). The application user's password lives in `VERITAS_DATABASE_URL`; rotate: `ALTER ROLE veritas PASSWORD ...`, update `veritas/<env>/runtime`, wait for External Secrets refresh (1 h) or force it, then `kv rollout restart deploy/veritas-api deploy/veritas-worker`. |
| ClickHouse password | Taint `module.stack.module.clickhouse.random_password.clickhouse`, apply, copy the new URL from `veritas/<env>/clickhouse` into `VERITAS_TIMELINE_URL`, restart. |
| API token signing key (`keys/token-signing.pem`) | Move the file aside in the data directory and restart the API pods; a new key is generated and all sessions end (users log in again). With OIDC, rotation is the IdP's. |
| `VERITAS_MASTER_KEY` | Not rotatable in place: every per-case data key and the examiner key vault key are derived from it, so a change makes existing evidence and sealed keys unreadable. If compromise is suspected, treat as a security incident: the evidence remains protected by SSE-KMS and IAM, rotate the KMS-side access, and plan a supervised re-encryption migration. Keep the escrow copies in sync (docs/DR.md). |
| Recovery X25519 key (backups) | `backup.py keygen`, store the private key with the custodians, update `VERITAS_BACKUP_RECIPIENT`; keep old private keys as long as archives sealed to them are retained (90 days). |
| Release signing | Keyless (cosign + GitHub OIDC): nothing to rotate. Windows/macOS code-signing certificates: replace the GitHub secrets before expiry. |

## 4. Revoking a compromised examiner key

Examiner signing keys are Ed25519 keys held server-side (sealed with a key derived from the master key);
the public key and validity window are in the key registry used by every verifier.

1. Disable the account and revoke the key in one call (admin):
   `PATCH /api/v1/admin/users/<user>` with `{"active": false}` — this sets `valid_to` on the user's key
   and deletes the sealed seed. Or revoke only the key: `POST /api/v1/admin/keys/<user>/revoke`.
2. With OIDC, also disable the user at the identity provider.
3. Find what the key signed after the suspected compromise time: for each case the user belongs to,
   `GET /api/v1/cases/<case>/custody?limit=100000` and filter on `actor_key_id`; audit log:
   `GET /api/v1/admin/audit?actor=<user>`.
4. Entries signed before `valid_to` remain valid for the verifier; entries after it fail verification by
   design. For entries inside the suspected window, add a `note` custody entry per case describing the
   incident and have the case lead review every affected finding and report.
5. Re-enable later with a fresh key: set `active: true`; the next action creates a new key pair and a new
   registry record.

## 5. Legal hold

* Place: `PATCH /api/v1/cases/<case>` with `{"legal_hold": true}` (case lead or admin). The retention sweep
  never lists a case on hold.
* Evidence objects are already COMPLIANCE-locked for the default retention. For holds that may outlast
  it, also set an S3 legal hold on the case's objects (API IRSA role allows `s3:PutObjectLegalHold`):
  `aws s3api put-object-legal-hold --bucket <bucket> --key objects/<aa>/<bb>/<sha256> --legal-hold Status=ON`
  for every evidence `sha256` of the case (`GET /api/v1/cases/<case>/evidence`).
* Release: `{"legal_hold": false}` and `Status=OFF` on the objects. Both actions are in the audit log.

## 6. Retention and disposal

1. `POST /api/v1/admin/retention/sweep` lists cases past `retention_until` and not on legal hold. It
   deletes nothing.
2. Disposal needs written approval from the case lead and records management. Export first:
   custody export, final report, timeline export, audit-log extract for the case.
3. Timeline rows: `TimelineStore.delete_case` (SQLite/ClickHouse) from an API pod. Case database rows:
   database change under change control. Evidence objects in S3 cannot be deleted before their Object
   Lock retention date (COMPLIANCE); after it, delete through a separately authorised role (no Veritas
   role has `s3:DeleteObject`), and record a final `note` custody entry and the deletion manifest.

## 7. Restoring

See `docs/DR.md` section 3 for the case-database PITR, data-directory, regional and native procedures,
and section 4 for the mandatory verification.

## 8. Verifying custody for court

1. `GET /api/v1/cases/<case>/custody/export` (examiner) — a self-contained JSON with all entries, the key
   registry, the anchors and the exporter's signature.
2. Verify with the independent binary from a signed release (verify the release first, `docs/SECURITY.md`):
   `veritas-verify export <case>-custody.json` → prints entries, signatures, anchors checked, chain head
   and `PASS`/`FAIL`; `--json` produces the full machine-readable report.
3. Show that the anchors match externally recorded head hashes (anchor sink receipts).
4. For each evidence item, the `ingest` entry's SHA-256/MD5/SHA3-256 equals the hash of the object
   produced in court; `POST /api/v1/cases/<case>/evidence/<id>/verify` re-hashes the stored object and
   records an `access` entry.
5. Provide the report together with its `.sig.json` (Ed25519 signature over the report SHA-256, signer key
   id present in the registry) and the `transform` ledger entry that recorded its generation.

## 9. Secrets and platform add-ons

* Runtime secret `veritas/<env>/runtime` (Secrets Manager, created empty by Terraform) holds
  `VERITAS_DATABASE_URL` (`postgresql+psycopg://veritas:<pw>@<rds-endpoint>/veritas?sslmode=verify-full`),
  `VERITAS_TIMELINE_URL` (from `veritas/<env>/clickhouse`), `VERITAS_MASTER_KEY`,
  `VERITAS_SERVICE_KEY_SEED` and `VERITAS_BACKUP_RECIPIENT`. Two custodians write it; nobody else has
  `secretsmanager:PutSecretValue`.
* Cluster add-ons installed outside this chart: ingress-nginx (Service bound to the Terraform ALB target
  group with an AWS Load Balancer Controller `TargetGroupBinding`), cert-manager with the
  `letsencrypt-prod`/`letsencrypt-staging` ClusterIssuers, External Secrets Operator with the
  `aws-secrets-manager` ClusterSecretStore, kube-prometheus-stack with a Pushgateway, KEDA, and for
  production workers a node pool with the gVisor (`runsc`) containerd handler.
* The API needs egress to the OIDC provider's JWKS URL; if the IdP is outside the cluster add its CIDR
  to `networkPolicy.apiExtraEgress`.
