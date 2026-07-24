# Phase B – Status

**Status**: Complete (adaptor extractable opening + simulation + live regtest)

## What changed vs Phase A

| Piece | Phase A | Phase B |
|-------|---------|---------|
| Opening | `DirectSeedOpening` (32-byte seed) | `AdaptorOpening` (Schnorr adaptor offset) |
| Extraction | Re-derive seed from claim | Recover `t = s − s'`, check `T = t·G` |
| Taproot connector | Disprove hashlock + Timeout CSV | **Unchanged** |
| Circuit backend | Claim Mini / GSV stand-in | **Unchanged** |

```
src/phase_b/
├── adaptor.rs   ← BIP340 sig + s' = s − t create/extract
├── opening.rs   ← AdaptorOpening witness layout
└── flow.rs      ← Assert → extract → Evaluate → Disprove / Timeout
```

Shared: `src/opening.rs` (`LabelOpening`, `AssertOpening`).

## Cryptographic shape

1. Engine samples adaptor secret `t`, publishes x-only `T = t·G`.
2. Engine BIP340-signs the claim-bound message → `(R, s)`.
3. Assert carries adapted scalar `s' = s − t` and completed `s`.
4. Challenger extracts `t`, verifies `T` and the completed signature, then
   derives label material `SHA256("CubePhaseBLabels" ‖ t)`.

This is the adaptor-offset construction that Phase C will wire into full
VSSS wide-label reconstruction from `garbled-snark-verifier`.

## Commands

```bash
# Simulation
cargo run --example phase_a_driver --no-default-features -- --adaptor
cargo run --example phase_a_driver --no-default-features -- --adaptor --cheat

# Live regtest (Docker — see docs/12-regtest-guide.md)
export BEACON_RPC_URL=http://127.0.0.1:18443 BEACON_RPC_USER=beacon BEACON_RPC_PASS=beacon
cargo run --example phase_a_driver --no-default-features -- --adaptor --regtest
cargo run --example phase_a_driver --no-default-features -- --adaptor --regtest --cheat
```

## Upgrade path

- **Phase C**: VSSS share reconstruction + full garbled Groth16 Evaluate  
  (adaptor secret becomes a verified share; same Disprove hashlock)
