# Integration tests

Beacon ships integration crates under `tests/`. Prefer the all-in-one runner:

```bash
./contrib/run-tests.sh                  # default matrix
./contrib/run-tests.sh --with-ignored --release   # + Docker regtest + C+ test

# Minutes-long garbled Groth16 (example path, not the fast matrix)
./contrib/run-phase-c-plus.sh           # honest + cheat at --k 4
```

| Suite | Features | What it covers |
|-------|----------|----------------|
| `integration_core` | none | Claim Mini, Phase A/B/C stand-in, AssertWitness, Taproot builders, ciphertext store (SHA256), cut-and-choose schedule |
| `integration_gsv` | `gsv` | Linked GSV backend, AND garble persist / evaluate-from-store, C&C re-garble |
| `integration_gsv_vsss` | `gsv-vsss` | Tag-3 `GsvAdaptorOpening`, Fr extract, ShareBundle, witness round-trip |
| `integration_regtest` | none | Docker bitcoind Assert → Disprove/Timeout (`#[ignore]`) |

## Commands (manual)

```bash
# Default CI-friendly (no GSV link)
cargo test --test integration_core --no-default-features

# GSV AND path (use a directory named `target` for SP1 build scripts)
export CARGO_TARGET_DIR=./target
cargo test --test integration_gsv --features gsv --no-default-features
cargo test --test integration_gsv_vsss --features gsv-vsss --no-default-features

# Optional heavy / Docker
cargo test --test integration_gsv --features gsv --release -- --ignored
cargo test --test integration_regtest --no-default-features -- --ignored
```

## Coverage stance

These suites aim for **behavioral coverage of every Beacon-owned public API path** that can run in a reasonable CI budget (Claim Mini, witness packing, Taproot builders, store, schedule, AND garble, GSV adaptor wire).

They do **not** claim LLVM line coverage of upstream `garbled-snark-verifier` or a full multi-minute Phase C+ Groth16 garble in the default run. That path is gated behind `#[ignore]` on `phase_c_plus_garbled_groth16_happy_and_cheat`. Regtest is likewise ignored until Docker bitcoind is up.
