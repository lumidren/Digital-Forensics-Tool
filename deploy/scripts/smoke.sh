#!/usr/bin/env bash
# Post-deploy smoke test for a Veritas release (used by .github/workflows/deploy.yml).
#   deploy/scripts/smoke.sh <namespace> <release> <public-host>
# Checks, in order:
#   1. /healthz and /readyz on the API Service (port-forward, cluster-internal endpoints);
#   2. a canary timeline search executed inside an API pod against the configured backend
#      (ClickHouse in the cluster profile), read-only, must answer in under 1 s;
#   3. the public path through ALB, WAF, ingress-nginx and TLS: the web UI and /api/v1/meta/roles.
# Exits non-zero on the first failure; the workflow then runs `helm rollback`.
set -euo pipefail

NS="$1"
RELEASE="$2"
HOST="$3"
SVC="${RELEASE}-veritas-api"
case "$RELEASE" in *veritas*) SVC="${RELEASE}-api" ;; esac
PORT=18080

echo "== port-forward svc/${SVC}"
kubectl -n "$NS" port-forward "svc/${SVC}" "${PORT}:8000" >/tmp/port-forward.log 2>&1 &
PF=$!
trap 'kill "$PF" 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 && break
  sleep 1
done

echo "== /healthz"
curl -fsS --max-time 10 "http://127.0.0.1:${PORT}/healthz"
echo
echo "== /readyz"
curl -fsS --max-time 10 "http://127.0.0.1:${PORT}/readyz"
echo

echo "== canary search (inside an API pod)"
kubectl -n "$NS" exec "deploy/${SVC}" -c api -- python - <<'PY'
import sys, time
from veritas.api.config import load
from veritas.timeline.store import Query, open_store

store = open_store(load().timeline_url)
t0 = time.perf_counter()
result = store.search("smoke-canary", Query(text="veritas canary", limit=1))
elapsed = time.perf_counter() - t0
print(f"canary search: total={result.total} latency={elapsed:.3f}s")
sys.exit(0 if elapsed < 1.0 else 1)
PY

echo "== public endpoints via https://${HOST}"
curl -fsS --max-time 15 -o /dev/null -w "web %{http_code} tls=%{ssl_verify_result}\n" "https://${HOST}/"
curl -fsS --max-time 15 "https://${HOST}/api/v1/meta/roles"
echo
echo "smoke test PASS"
