# Phase A Driver

**Binary**: `examples/phase_a_driver.rs`

## Commands

```bash
# Simulation
cargo run --example phase_a_driver
cargo run --example phase_a_driver -- --cheat
cargo run --example phase_a_driver -- --adaptor
cargo run --example phase_a_driver -- --adaptor --cheat
cargo run --example phase_a_driver -- --gsv --cheat

# Live regtest (needs bitcoind / Docker)
cargo run --example phase_a_driver -- --regtest
cargo run --example phase_a_driver -- --regtest --cheat
cargo run --example phase_a_driver -- --adaptor --regtest --cheat
```

## Files

| File | Role |
|------|------|
| `examples/phase_a_driver.rs` | CLI (`--adaptor` selects Phase B) |
| `src/phase_a/flow.rs` | Phase A logical flow |
| `src/phase_a/opening.rs` | DirectSeedOpening |
| `src/phase_b/` | Adaptor opening + Phase B flow |
| `src/phase_a/regtest_tx.rs` | Signed Taproot txs |
| `src/phase_a/regtest_run.rs` | RPC runner |

Phase B only changes the opening construction; the Taproot graph stays.
