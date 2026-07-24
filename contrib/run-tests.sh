#!/usr/bin/env bash
# Run Beacon's full default test matrix (unit + integration).
#
# Usage (from anywhere):
#   ./contrib/run-tests.sh
#   ./contrib/run-tests.sh --with-ignored   # also run #[ignore] (needs Docker for regtest; C+ is slow)
#   ./contrib/run-tests.sh --release        # build/test with --release (recommended with --with-ignored for C+)
#   ./contrib/run-tests.sh --help
#
# Environment:
#   CARGO_TARGET_DIR   defaults to ./target (required for GSV / SP1 build scripts)
#   BEACON_RPC_URL     used only when --with-ignored runs integration_regtest
#   BEACON_RPC_USER / BEACON_RPC_PASS
#
# Exit: non-zero if any suite fails.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WITH_IGNORED=0
RELEASE_FLAG=()
CARGO_ARGS=()

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \?//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-ignored|-i)
      WITH_IGNORED=1
      shift
      ;;
    --release|-r)
      RELEASE_FLAG=(--release)
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

# GSV / SP1 build scripts expect a directory literally named "target".
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-./target}"

PASS=0
FAIL=0
SKIP=0

section() {
  echo
  echo "════════════════════════════════════════════════════════════"
  echo " $*"
  echo "════════════════════════════════════════════════════════════"
}

run_suite() {
  local title="$1"
  shift
  section "$title"
  echo "+ $*"
  if "$@"; then
    echo "→ OK: $title"
    PASS=$((PASS + 1))
  else
    echo "→ FAIL: $title" >&2
    FAIL=$((FAIL + 1))
  fi
}

echo "Beacon test runner"
echo "  root=$ROOT"
echo "  CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
echo "  release=${RELEASE_FLAG[*]:-no}"
echo "  with_ignored=$WITH_IGNORED"

# ---------------------------------------------------------------------------
# 1) Fast path — no GSV link (MIT-only Claim Mini + core + regtest harness)
# ---------------------------------------------------------------------------
run_suite "unit + integration_core + integration_regtest (no-default-features)" \
  cargo test --no-default-features "${RELEASE_FLAG[@]}"

# ---------------------------------------------------------------------------
# 2) GSV-linked AND persist / C&C (default ignored C+ stays ignored here)
# ---------------------------------------------------------------------------
run_suite "integration_gsv (features=gsv)" \
  cargo test --test integration_gsv --features gsv --no-default-features "${RELEASE_FLAG[@]}"

# ---------------------------------------------------------------------------
# 3) GSV VSSS adaptor wire (tag 3)
# ---------------------------------------------------------------------------
run_suite "integration_gsv_vsss (features=gsv-vsss)" \
  cargo test --test integration_gsv_vsss --features gsv-vsss --no-default-features "${RELEASE_FLAG[@]}"

# ---------------------------------------------------------------------------
# 4) Optional #[ignore] suites
# ---------------------------------------------------------------------------
if [[ "$WITH_IGNORED" -eq 1 ]]; then
  run_suite "integration_regtest --ignored (Docker bitcoind)" \
    cargo test --test integration_regtest --no-default-features "${RELEASE_FLAG[@]}" -- --ignored --nocapture

  run_suite "integration_gsv Phase C+ --ignored (slow Groth16)" \
    cargo test --test integration_gsv --features gsv --no-default-features "${RELEASE_FLAG[@]}" -- --ignored --nocapture
else
  section "skipped #[ignore] suites (pass --with-ignored to enable)"
  echo "  - integration_regtest (needs BEACON_RPC_* + Docker)"
  echo "  - phase_c_plus_garbled_groth16_happy_and_cheat (minutes; prefer --release)"
  SKIP=$((SKIP + 2))
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
section "summary"
echo "  passed suites: $PASS"
echo "  failed suites: $FAIL"
echo "  skipped opts:  $SKIP"
echo

if [[ "$FAIL" -ne 0 ]]; then
  echo "FAILED" >&2
  exit 1
fi
echo "ALL DEFAULT SUITES PASSED"
exit 0
