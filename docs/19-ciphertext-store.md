# Ciphertext Store (cut-and-choose persistence)

**Status**: MVP — disk store + hash verify + Evaluate-from-store (Phase C tiny AND; C+ API)

## Cube / whitepaper fit

Cut-and-choose commits to garbled-circuit **ciphertext hashes** off-chain. Assert
still only publishes opening + `H(L*)` (+ public statement). Challengers load the
stream for instance `a`, check the hash, then Evaluate.

```text
Engine:  garble → write gc_{a}.bin → commit ciphertext_hash
Assert:  opening + H(L*) (+ claim_bytes)     ← on-chain / OP_RETURN
Challenger: verify hash → Evaluate from disk → Timeout | Disprove
```

No change to Taproot leaves. CT never goes in the Assert witness.

## Layout

```text
{store_root}/
  gc_{instance_id}.bin        # GSV format: concatenated 16-byte BE S labels
  gc_{instance_id}.meta.json  # CiphertextMeta (hash, seed, wires, L*)
  gc_{instance_id}.pkg.json   # Phase C AND eval package (input wire labels)
```

| Field | Meaning |
|-------|---------|
| `ciphertext_hash` | Blake3 accumulating hash (`blake3-accum`) or SHA256 of file (tests) |
| `instance_id` | Cut-and-choose evaluation instance `a` |
| `l_invalid` / `l_valid` | Expanded Disprove / Accept labels |
| `seed` / wires | Needed for gate hasher / evaluate constants |

Module: [`src/phase_c/ciphertext_store.rs`](../src/phase_c/ciphertext_store.rs)  
Phase C AND persist: [`src/phase_c/persist.rs`](../src/phase_c/persist.rs)  
Phase C+ hooks: `setup_garble_to_store` / `evaluate_bundle_from_store` in `groth16.rs`

## Commands

```bash
# Store API (no GSV)
cargo test --no-default-features ciphertext_store

# Tiny AND: garble → disk → evaluate (needs gsv)
export CARGO_TARGET_DIR=./target
cargo test --features gsv --no-default-features persist_
cargo run --example phase_c_persist --features gsv --no-default-features
```

## Related

- Schedule MVP: [`20-cut-and-choose-schedule.md`](20-cut-and-choose-schedule.md)
- Assert optional `ciphertext_hash`: [`18-assert-witness.md`](18-assert-witness.md)
- Eval sidecar + check-set re-garble: [`22-eval-sidecar.md`](22-eval-sidecar.md)

## Still open

- Full VSSS / wide-label C&C (beyond hash re-garble of toy AND)
- Wire GSV `AdaptorInfo` multi-adaptor (`WideAdaptorInfo`)
