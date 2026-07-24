# Phase A – Status

**Status**: Complete (simulation + signed Taproot + live regtest)

## What works

```
src/phase_a/
├── opening.rs      ← DirectSeedOpening
├── flow.rs         ← Assert → Evaluate → Disprove / Timeout (logical)
├── regtest_tx.rs   ← Taproot builders + real Schnorr signatures
└── regtest_run.rs  ← bitcoind RPC end-to-end runner
```

| Path | Result |
|------|--------|
| Honest Engine | Assert → mine CSV → Timeout |
| Cheating Engine | Assert → Disprove with `L*` |

```bash
cargo run --example phase_a_driver -- --regtest
cargo run --example phase_a_driver -- --regtest --cheat
```

## On-chain shape

- Connector: Taproot with **NUMS** internal key (script-path only)
- Disprove leaf: `OP_SHA256 <H(L*)> OP_EQUALVERIFY OP_TRUE`
- Timeout leaf: `<Δ> OP_CSV OP_DROP <engine_xonly> OP_CHECKSIG`
- Regtest CSV window: `REGTEST_DISPUTE_WINDOW = 2`

## Upgrade path

- **Phase B**: replace `DirectSeedOpening` with adaptor-signature opening  
- **Phase C**: VSSS + full garbled Groth16 Evaluate  

Taproot leaves and Disprove / Timeout stay the same.
