# Phase A Driver

**Binary**: `examples/phase_a_driver.rs`

## Commands

```bash
# Simulation
cargo run --example phase_a_driver
cargo run --example phase_a_driver -- --cheat
cargo run --example phase_a_driver -- --gsv --cheat

# Live regtest (needs bitcoind)
cargo run --example phase_a_driver -- --regtest
cargo run --example phase_a_driver -- --regtest --cheat
```

## Files

| File | Role |
|------|------|
| `examples/phase_a_driver.rs` | CLI |
| `src/phase_a/flow.rs` | Logical flow |
| `src/phase_a/opening.rs` | DirectSeedOpening |
| `src/phase_a/regtest_tx.rs` | Signed Taproot txs |
| `src/phase_a/regtest_run.rs` | RPC runner |

Phase B only changes the opening construction; the driver / Taproot graph stay.
