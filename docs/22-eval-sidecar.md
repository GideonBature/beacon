# Phase C+ Eval Sidecar + Check-Set Re-garble

**Status**: Implemented (`gsv`)

## Eval sidecar

After `setup_garble_to_store`, the store holds:

```text
gc_{a}.bin              # garbled CT stream (GSV FileCiphertextHandler)
gc_{a}.meta.json        # CiphertextMeta (+ optional sidecar_file/hash)
gc_{a}.eval.bin         # Groth16EvalSidecar (VK, proof, publics, input wires)
```

Challenger path (no Engine RAM bundle):

```text
evaluate_from_store(store, a)
  → verify CT hash
  → verify sidecar SHA256
  → streaming_evaluation from disk
```

Module: [`src/phase_c/sidecar.rs`](../src/phase_c/sidecar.rs).

Cube fit: CT + eval materials stay **off-chain**; Assert still only needs opening +
`H(L*)` (+ optional `ciphertext_hash`).

## Check-set re-garble

For Phase C tiny AND instances:

```text
verify_check_regarble(store, check_openings)
  → for each i∈C: re-garble(seed) → Blake3-accum hash == meta.ciphertext_hash
```

This is the MVP consistency check after cut-and-choose open (not full Commit₁
label reopen). See [`20-cut-and-choose-schedule.md`](20-cut-and-choose-schedule.md).

## Commands

```bash
export CARGO_TARGET_DIR=./target
cargo test --features gsv --no-default-features sidecar_ check_set_regarble
```

Full C+ evaluate-from-store still needs a prior `--release` `setup_garble_to_store`
run (minutes at `--k 4`).
