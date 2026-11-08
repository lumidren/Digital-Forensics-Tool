# Test coverage

## Rust

Measured with `cargo llvm-cov --workspace --summary-only` (cargo-llvm-cov 0.9.1, Rust stable,
Windows 11) on 2026-11-09. CI repeats the measurement on every push and fails below 78 % of lines.

| Crate | Lines | Line coverage |
|---|---:|---:|
| `veritas-hash` | 72 | 97.2% |
| `veritas-store` | 369 | 95.4% |
| `veritas-timeline` | 151 | 92.7% |
| `veritas-artifacts` | 8022 | 84.1% |
| `veritas-fs` | 6018 | 83.2% |
| `veritas-ewf` | 1749 | 80.5% |
| `veritas-aff4` | 2759 | 80.1% |
| `veritas-ledger` | 836 | 79.9% |
| `veritas-agent` | 4012 | 67.2% |
| `veritas-cli` | 259 | 10.4% |
| **Workspace** | **24247** | **79.7%** |

Regions: 77.6 %. Functions: 78.7 %.

Reading the numbers:

* The `veritas-cli` binary and `fs-tool` are thin argument parsers over the library crates. Their
  behaviour is covered by the Python suite (`python/tests`), which runs them as subprocesses; those
  runs are not part of this Rust-only measurement.
* `veritas-agent` is lowest among the libraries because the live collectors (WinPmem, LiME,
  osxpmem, raw volume reads) need administrator rights and a real host. The imaging, manifest and
  upload paths are covered, and `python/tests/unit/test_agent_mtls.py` drives the release binary
  through a real mutual-TLS upload.
* `veritas-ledger/src/verify.rs` (57 %) is mostly the export verifier's error reporting; the
  PASS/FAIL paths are covered by `python/tests/unit/test_retention.py` and the ledger property tests.

Reproduce:

```bash
cargo install cargo-llvm-cov --locked
cargo llvm-cov --workspace --locked --summary-only
```

## Python

`pytest --cov=veritas` with a 90 % gate in CI (see `.github/workflows/ci.yml`).
