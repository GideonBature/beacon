# Phase A Driver

**Binary**: `examples/phase_a_driver.rs`

## What it does

Runs the complete Phase A flow:

1. Engine creates a ClaimMini (honest or cheating with `--cheat`)
2. Engine builds Assert + DirectSeedOpening + H(L_invalid)
3. Challenger evaluates the claim
4. If invalid → builds Disprove with L_invalid
5. If valid   → shows that Engine can later Timeout

## How to run

```bash
# Pure simulation (no Bitcoin node needed)
cargo run --example phase_a_driver

# Engine tries to cheat
cargo run --example phase_a_driver -- --cheat

# Attempt to talk to regtest (falls back to simulation until
# real script-path signatures are finished)
cargo run --example phase_a_driver -- --regtest
```

## Current limitations

- The driver demonstrates the **full logical protocol**.
- Real signed broadcast on regtest still requires:
  - Signing the Assert input with the funding key
  - Producing a real Taproot script-path Schnorr signature for the Timeout leaf
- The transaction builders in `src/phase_a/regtest_tx.rs` already construct the correct Taproot structure and witness layout; only the final signatures are placeholders.

## Upgrade path

Once the driver works end-to-end on regtest with real signatures:

- Phase B replaces `DirectSeedOpening` with an adaptor-signature opening
- Phase C adds full VSSS share reconstruction
- The driver itself stays almost identical; only the opening construction changes

## Files involved

| File | Role |
|------|------|
| `examples/phase_a_driver.rs` | Entry point |
| `src/phase_a/flow.rs` | High-level Assert → Evaluate → Disprove/Timeout |
| `src/phase_a/opening.rs` | DirectSeedOpening |
| `src/phase_a/regtest_tx.rs` | Real Taproot transaction builders |
| `src/claim_mini.rs` | The verification circuit used in Phase A |
