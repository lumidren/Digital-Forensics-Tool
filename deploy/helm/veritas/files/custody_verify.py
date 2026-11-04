"""Scheduled custody verification (CronJob): ``python -m veritas.api.manage verify-custody <case>`` for every case.

Pushes to the Prometheus Pushgateway (job ``veritas-custody-verify``):
  veritas_custody_verify_ok{case_id}                    1 PASS / 0 FAIL  (alert VeritasCustodyVerifyFailed)
  veritas_custody_verify_last_run_timestamp_seconds     (alert VeritasCustodyVerifyStale)
  veritas_custody_verify_cases / _failed_cases / _duration_seconds
Exits 1 when any ledger fails, so the Job is also marked failed.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

from veritas.api.config import load
from veritas.api.db import Case, make_engine, make_sessionmaker


def main() -> int:
    t0 = time.perf_counter()
    settings = load()
    session = make_sessionmaker(make_engine(settings.database_url))
    with session() as s:
        case_ids = sorted(c.id for c in s.query(Case))
    reg = CollectorRegistry()
    ok_g = Gauge("veritas_custody_verify_ok", "1 if the case custody ledger verified, 0 otherwise", ["case_id"], registry=reg)
    failed = []
    for case_id in case_ids:
        proc = subprocess.run([sys.executable, "-m", "veritas.api.manage", "verify-custody", case_id], capture_output=True, text=True, check=False, timeout=3600)
        ok = proc.returncode == 0
        ok_g.labels(case_id).set(1 if ok else 0)
        print(f"{'PASS' if ok else 'FAIL'} {case_id}", flush=True)
        if not ok:
            failed.append(case_id)
            print(proc.stdout[-2000:], proc.stderr[-2000:], sep="\n", flush=True)
    Gauge("veritas_custody_verify_cases", "Cases verified in the last run", registry=reg).set(len(case_ids))
    Gauge("veritas_custody_verify_failed_cases", "Cases that failed verification in the last run", registry=reg).set(len(failed))
    Gauge("veritas_custody_verify_duration_seconds", "Duration of the last verification run", registry=reg).set(time.perf_counter() - t0)
    Gauge("veritas_custody_verify_last_run_timestamp_seconds", "Unix time of the last completed run", registry=reg).set_to_current_time()
    gateway = os.environ.get("VERITAS_PUSHGATEWAY_URL")
    if gateway:
        push_to_gateway(gateway, job="veritas-custody-verify", registry=reg)
    print(f"verified {len(case_ids)} case(s), {len(failed)} failed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
