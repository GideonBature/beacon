# Pluggable Circuit Backend

**Status**: Implemented (Claim Mini live; GSV stand-in ready for real crate)

## Shape

```text
CircuitBackend trait
├── ClaimMiniBackend          ← Phase A (works today)
└── GarbledSnarkBackend       ← real BitVM3 path (stand-in + integration contract)
```

On-chain Assert / Disprove / Timeout templates do **not** change when the
backend switches. Only `commit_l_invalid` and `evaluate` do.

## Hashlock rule

```text
H(L_invalid) = SHA256(L*)
```

This matches the Disprove Taproot leaf (`OP_SHA256 <H> OP_EQUALVERIFY`).

## CLI

```bash
cargo run --example phase_a_driver              # claim-mini
cargo run --example phase_a_driver -- --gsv     # garbled-snark-verifier stand-in
cargo run --example phase_a_driver -- --gsv --cheat
```

## Linking the real library

[`garbled-snark-verifier`](https://github.com/BitVM/garbled-snark-verifier) is
not a Cargo dependency yet (edition 2024 / Rust 1.90 / heavy default features).

When ready:

```toml
garbled-snark-verifier = { git = "https://github.com/BitVM/garbled-snark-verifier", default-features = false }
```

Replace the stand-in body of `GarbledSnarkBackend::evaluate` with:

1. Recover labels from the Assert opening  
2. Call the library in **Evaluate** mode  
3. Return `L_valid` or `L_invalid` from the garbled circuit  

`commit_l_invalid` should use the `H(L_invalid)` published at GSV setup.
