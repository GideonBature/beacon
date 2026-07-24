# Cut-and-Choose Schedule (MVP)

**Status**: Implemented — schedule + check-set open + eval CT bind into Assert

## Cube / whitepaper fit

Maps docs/09 Steps 2–4 without full VSSS / soldering:

```text
Setup:  garble n instances → CiphertextStore; publish InstanceCommit[]
Select: sample/fixed schedule → check set C, eval set E, Assert instance a∈E
Open:   Engine opens C (seeds + store hash verify)
Assert: opening.instance_id=a + optional ciphertext_hash(a) + H(L*)
Eval:   verify store vs witness hash → Evaluate → Timeout | Disprove
```

Taproot leaves unchanged. Check openings stay **off-chain** (epoch / bulletin board).

## Types

| Type | Role |
|------|------|
| `CutAndChooseParams { n, eval_count }` | GSV Config shape (`f=eval_count`, MVP default 1) |
| `CutAndChooseSchedule` | Partition `C` / `E` + `eval_instance` |
| `InstanceCommit` | Published `ciphertext_hash` per instance |
| `CheckOpening` | Seed (+ hash via store) for each `i∈C` |

Module: [`src/phase_c/schedule.rs`](../src/phase_c/schedule.rs).

## Assert witness

`AssertWitnessV1` may carry optional `ciphertext_hash` for instance `a`
(trailing flag after `share_bundle`; older blobs without the flag still decode).
See [`18-assert-witness.md`](18-assert-witness.md).

## Commands

```bash
cargo test --no-default-features schedule::
cargo test --no-default-features ciphertext_hash

export CARGO_TARGET_DIR=./target
cargo run --example phase_c_cnc --features gsv --no-default-features
```

## Check-set re-garble

`verify_check_regarble` (Phase C AND) re-garbles each opened check instance from
`meta.seed` and checks the Blake3-accumulating CT hash. See
[`22-eval-sidecar.md`](22-eval-sidecar.md).

## Not in this MVP

- Full Commit₁ label-commit reopen (beyond CT hash)
- `f > 1` multi-eval Assert policy
- VSSS wide labels / `WideAdaptorInfo`
- Putting check openings on-chain
