# Phase C+ – Status

**Status**: Implemented — real `garbled_groth16::verify` Garble → Evaluate  
**Runtime**: prefer `--release` (debug is impractically slow)

## What it is

Phase C MVP garbles a toy AND. Phase C+ garbles the **full BN254 Groth16
verifier gadget** from [garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier)
(same shape as upstream `examples/gsv_garble.rs`).

```
src/phase_c/
├── groth16.rs   ← setup / prove / garble / evaluate bundle
└── plus.rs      ← PhaseCPlusFlow (adaptor + hashlock + Groth16)
```

| Step | Action |
|------|--------|
| Setup | `DummyCircuit` (stand-in for Cube SNARK), `2^k` constraints |
| Garble | `CircuitBuilder::streaming_garbling(..., garbled_groth16::verify)` |
| Commit | `H(L_invalid) = SHA256(expand(output.label0))` |
| Assert | Phase B adaptor opening + Groth16 bundle (off-chain for now) |
| Evaluate | Re-garble stream **or** load persisted CT (`evaluate_bundle_from_store`) |
| Dispute | Valid → Timeout; Invalid → Disprove with `L*` |

Taproot leaves stay unchanged. CT persist API: `setup_garble_to_store` (see
[`19-ciphertext-store.md`](19-ciphertext-store.md)).

## Commands

```bash
export CARGO_TARGET_DIR=./target

# Dedicated example (recommended)
cargo run --release --example phase_c_plus --features gsv --no-default-features
cargo run --release --example phase_c_plus --features gsv --no-default-features -- --cheat
cargo run --release --example phase_c_plus --features gsv --no-default-features -- --k 4 --cheat

# Driver flag
cargo run --release --example phase_a_driver --features gsv --no-default-features -- --phase-c-plus --k 4

# Ignored integration test
cargo test --release --features gsv --no-default-features --lib \
  phase_c::groth16::tests::groth16_garble_evaluate_valid_and_invalid -- --ignored
```

`--k N` sets DummyCircuit constraints to `2^N` (default **6**, matching upstream).  
Use `--k 4` for a quicker smoke; gate count of the *verifier gadget* still dominates.

## Features

| Feature | Role |
|---------|------|
| `gsv` / `gsv-groth16` | Enables Phase C+ modules + examples |
| `gsv-vsss` | Optional share reconstruct (still available to fold into seed) |

## What is still not production Cube

- Proof is over `DummyCircuit`, not CubeVM state transitions  
- CT can be persisted (`setup_garble_to_store`); proof/VK sidecar serialization still open  

- Multi-instance VSSS C&C (~11B gates / ~43 GB) remains upstream `gsv_vsss`  
- GSV `AdaptorInfo` (k256 / Fr shares) is not wire-compatible with Phase B yet  

Phase C+ proves Beacon can drive the **real garbled Groth16 Evaluate** into the
same Accept / Disprove hashlock contract.
