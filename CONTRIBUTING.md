# Contributing to Veritas DFIR

Veritas output can end up in court. Contributions are held to that standard: every parser change
must keep or improve agreement with reference tools, keep output deterministic, and never panic on
hostile input.

## Development setup (native, no containers needed)

```bash
python testdata/fetch.py                       # public reference corpus, hash-verified
cargo build --workspace --release
python -m venv .venv && .venv/Scripts/python -m pip install -e "python[parity,dev]"   # .venv/bin on Linux/macOS
```

## Before you open a pull request

| Check | Command |
|---|---|
| Rust format and lints | `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` |
| Rust tests | `cargo test --workspace --locked` |
| Python lint and types | `ruff check python` and `mypy python/veritas` |
| Python tests with coverage | `pytest python/tests --cov=veritas --cov-fail-under=90` |
| Parser parity | `pytest -m parity python/tests/parity` then `python scripts/parity_report.py` and `python scripts/parity_gate.py` |
| Determinism | `python scripts/determinism_check.py` |
| Threat-model references | `python scripts/check_threat_model.py` |
| Web | `cd web && npm run lint && npm run typecheck && npm test && npm run build && npx playwright test` |

CI runs all of these plus fuzz smoke tests, Semgrep, Trivy, cargo-audit, pip-audit and npm audit.
HIGH or CRITICAL findings fail the build.

## Rules for parser changes

1. **Parity is a gate.** A parser PR may not lower any field's agreement in `parity/baseline.json`.
   If a reference tool is wrong, document the case in the parity result `notes`, add a fixture that
   shows the correct behaviour, and update the baseline in the same PR with an explanation.
2. **No panics, no `unsafe`.** Rust parsers use the bounds-checked readers in `util.rs`; every
   length field is checked; loops and recursion are capped. Add a fuzz target for every new binary
   format and run it for at least ten minutes locally.
3. **Determinism.** No wall clock, no random numbers, no hash-map iteration order in output.
   Use `BTreeMap` in Rust and sorted keys in Python.
4. **Provenance.** Every event names the evidence hash, the path inside the evidence, the byte
   offset or record number, and the parser version.
5. **Plaso vocabulary.** Use Plaso `data_type` and `timestamp_desc` names where they exist.

## Rules for custody and security code

- Changes to `crates/veritas-ledger`, `python/veritas/custody` or the canonical JSON rules need two
  reviewers, one of whom maintains the verifier.
- Never log secrets. The `test_no_secrets_in_logs.py` test must keep passing.
- If you add or move a mitigation, update `docs/THREAT_MODEL.md` and run
  `python scripts/check_threat_model.py --update`.

## Commits

Small commits, one logical change each, imperative subject line with a conventional prefix
(`feat`, `fix`, `docs`, `test`, `build`, `ci`, `refactor`, `chore`).
