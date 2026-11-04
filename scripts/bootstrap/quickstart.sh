#!/usr/bin/env bash
# Veritas native quickstart (Linux, macOS, Git Bash on Windows). No container runtime is used.
#   1. create .venv and install the Python package with the parity extra
#   2. build the Rust binaries (veritas, veritas-verify, fs-tool, ...) with the committed lockfile
#   3. start the API on 127.0.0.1:${VERITAS_PORT:-8000} with data in ./var
#   4. run scripts/bootstrap/sample_case.py against it
#   5. print the web URL
# Usage: scripts/bootstrap/quickstart.sh [--full] [--no-build]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PORT="${VERITAS_PORT:-8000}"
WEB_URL="${VERITAS_WEB_URL:-http://localhost:3000}"
BUILD=1
SAMPLE_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    --full) SAMPLE_ARGS+=("--full") ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [[ "${OS:-}" == "Windows_NT" ]]; then
  PY_BOOT="${PYTHON:-py -3.12}"
  VENV_PY="$ROOT/.venv/Scripts/python.exe"
else
  PY_BOOT="${PYTHON:-python3.12}"
  VENV_PY="$ROOT/.venv/bin/python"
fi

echo "==> [1/5] Python environment (.venv)"
if [[ ! -x "$VENV_PY" ]]; then
  $PY_BOOT -m venv "$ROOT/.venv"
fi
"$VENV_PY" -m pip install --upgrade pip >/dev/null
"$VENV_PY" -m pip install -e "python[parity]"

echo "==> [2/5] Rust binaries (cargo build --release --locked)"
if [[ "$BUILD" == "1" ]]; then
  cargo build --release --locked
fi
export VERITAS_BIN_DIR="$ROOT/target/release"
export VERITAS_DATA_DIR="${VERITAS_DATA_DIR:-$ROOT/var}"
mkdir -p "$VERITAS_DATA_DIR"

echo "==> [3/5] API on http://127.0.0.1:${PORT} (data: $VERITAS_DATA_DIR)"
if "$VENV_PY" -c "import sys, urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/readyz', timeout=2); sys.exit(0)" 2>/dev/null; then
  echo "    an API is already answering on port ${PORT}; reusing it"
else
  "$VENV_PY" -m uvicorn veritas.api.main:create_app --factory --host 127.0.0.1 --port "$PORT" >"$VERITAS_DATA_DIR/api.log" 2>&1 &
  echo $! >"$VERITAS_DATA_DIR/api.pid"
  for _ in $(seq 1 60); do
    if "$VENV_PY" -c "import sys, urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/readyz', timeout=2)" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  "$VENV_PY" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/readyz', timeout=2)" \
    || { echo "API did not become ready; see $VERITAS_DATA_DIR/api.log" >&2; exit 1; }
  echo "    API pid $(cat "$VERITAS_DATA_DIR/api.pid"); log $VERITAS_DATA_DIR/api.log"
fi

echo "==> [4/5] sample case"
"$VENV_PY" scripts/bootstrap/sample_case.py --api "http://127.0.0.1:${PORT}" --web-url "$WEB_URL" ${SAMPLE_ARGS[@]+"${SAMPLE_ARGS[@]}"}

echo "==> [5/5] web UI"
echo "    start it with:  (cd web && npm ci && NEXT_PUBLIC_API_BASE=http://127.0.0.1:${PORT} npm run dev)"
echo "    then open:      ${WEB_URL}"
echo "    sign in as 'examiner' with the password in ${VERITAS_BOOTSTRAP_OUT:-$ROOT/var/bootstrap}/credentials.json"
echo "    stop the API:   kill \$(cat \"$VERITAS_DATA_DIR/api.pid\")"
