#!/usr/bin/env bash
# Run Beacon Phase C+ – full garbled Groth16 (Garble → Evaluate).
#
# This is the minutes-long path (BN254 verifier gadget). Prefer a quiet machine
# and enough RAM. Always builds/runs in --release unless you force --debug.
#
# Usage:
#   ./contrib/run-phase-c-plus.sh              # honest then cheat at --k 4
#   ./contrib/run-phase-c-plus.sh --k 6        # heavier DummyCircuit (default in example)
#   ./contrib/run-phase-c-plus.sh --honest-only
#   ./contrib/run-phase-c-plus.sh --cheat-only
#   ./contrib/run-phase-c-plus.sh --with-test  # also run ignored integration_gsv C+ test
#   ./contrib/run-phase-c-plus.sh --help
#
# Environment:
#   CARGO_TARGET_DIR   defaults to ./target (required for GSV / SP1 build scripts)
#   BEACON_CPLUS_K     default k if --k not passed (default: 4)
#
# Expect ~15–35+ minutes per run at k=4 on a laptop; k=6 is much slower.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

K="${BEACON_CPLUS_K:-4}"
RUN_HONEST=1
RUN_CHEAT=1
WITH_TEST=0
PROFILE=(--release)

usage() {
  sed -n '2,22p' "$0" | sed 's/^# \?//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --k)
      K="${2:?--k requires a value}"
      shift 2
      ;;
    --honest-only)
      RUN_HONEST=1
      RUN_CHEAT=0
      shift
      ;;
    --cheat-only)
      RUN_HONEST=0
      RUN_CHEAT=1
      shift
      ;;
    --with-test)
      WITH_TEST=1
      shift
      ;;
    --debug)
      PROFILE=()
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

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-./target}"

section() {
  echo
  echo "════════════════════════════════════════════════════════════"
  echo " $*"
  echo "════════════════════════════════════════════════════════════"
}

echo "Beacon Phase C+ runner (garbled Groth16)"
echo "  root=$ROOT"
echo "  CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
echo "  k=$K  constraints=$((1 << K))"
echo "  profile=${PROFILE[*]:-debug}"
echo "  honest=$RUN_HONEST  cheat=$RUN_CHEAT  with_test=$WITH_TEST"
echo
echo "NOTE: This path takes many minutes. Ctrl-C to abort."

FEATURES=(--features gsv --no-default-features)
EXAMPLE=(cargo run "${PROFILE[@]}" --example phase_c_plus "${FEATURES[@]}")

if [[ "$RUN_HONEST" -eq 1 ]]; then
  section "Phase C+ honest (valid proof → Valid / Timeout path)"
  echo "+ ${EXAMPLE[*]} -- --k $K"
  "${EXAMPLE[@]}" -- --k "$K"
fi

if [[ "$RUN_CHEAT" -eq 1 ]]; then
  section "Phase C+ cheat (broken proof → Invalid L* / Disprove path)"
  echo "+ ${EXAMPLE[*]} -- --k $K --cheat"
  "${EXAMPLE[@]}" -- --k "$K" --cheat
fi

if [[ "$WITH_TEST" -eq 1 ]]; then
  section "ignored integration test: phase_c_plus_garbled_groth16_happy_and_cheat"
  cargo test --test integration_gsv "${FEATURES[@]}" "${PROFILE[@]}" \
    phase_c_plus_garbled_groth16_happy_and_cheat -- --ignored --nocapture
fi

section "summary"
echo "  Phase C+ path finished (k=$K)."
echo "ALL PHASE C+ STEPS PASSED"
exit 0
