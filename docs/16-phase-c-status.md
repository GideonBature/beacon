# Phase C – Status

**Status**: Complete (MVP) — tiny garbled Evaluate + optional VSSS reconstruct  
**Not in scope for CI**: full garbled Groth16 (~11B gates / ~43 GB), deferred to upstream `gsv_vsss` release runs

## What works

```
src/phase_c/
├── labels.rs            ← expand GSV 16-byte labels → 32-byte L*
├── reconstruct.rs       ← ShareBundle + seed fold (`gsv-vsss` uses lagrange)
├── evaluate.rs          ← streaming_garbling → streaming_evaluation (AND toy)
├── ciphertext_store.rs  ← off-chain CT files + hash verify
├── persist.rs           ← garble-to-store / evaluate-from-store (gsv)
└── flow.rs              ← adaptor open → reconstruct → Evaluate → Disprove|Timeout
```

| Path | Result |
|------|--------|
| Honest Engine | Assert → Evaluate Valid → Timeout |
| Cheating Engine | Assert → Evaluate Invalid → Disprove with `L*` |

Taproot connector / Disprove / Timeout **unchanged**.

## Feature flags

| Feature | Meaning |
|---------|---------|
| *(none)* | Phase C stand-in (Claim Mini validity + domain-separated `L*`) |
| `gsv` | Real tiny Garble → Evaluate via `garbled-snark-verifier` |
| `gsv-vsss` | + upstream `lagrange_interpolate_whole_polynomial` |

Prefer `CARGO_TARGET_DIR=./target` when building with `gsv` (SP1 build-script quirk).

## Commands

```bash
# Stand-in (fast; Docker-friendly)
cargo run --example phase_a_driver --no-default-features -- --phase-c
cargo run --example phase_a_driver --no-default-features -- --phase-c --cheat
cargo run --example phase_a_driver --no-default-features -- --phase-c --regtest --cheat

# Real garbled Evaluate
export CARGO_TARGET_DIR=./target
cargo run --example phase_c_garble --features gsv --no-default-features
cargo run --example phase_a_driver --features gsv --no-default-features -- --phase-c --cheat

# Optional VSSS lagrange path
cargo test --features gsv-vsss --no-default-features phase_c
```

## Cryptographic shape

1. Phase B adaptor opening → extract secret / label material  
2. Optional `ShareBundle` (check-set) folded with adaptor share → evaluation seed  
3. Deterministic garble seed → toy AND circuit (`flag ∧ true`)  
4. `L_invalid = expand(output.label0)` committed in Disprove hashlock  
5. Challenger Evaluate: active label → Accept or Disprove  

## Next

- **Phase C+**: done — see [`17-phase-c-plus-status.md`](17-phase-c-plus-status.md)  
- **Ciphertext store MVP**: done — see [`19-ciphertext-store.md`](19-ciphertext-store.md)  
- Still open: multi-instance C&C schedule, Cube VK proofs, GSV `AdaptorInfo` wire compat
