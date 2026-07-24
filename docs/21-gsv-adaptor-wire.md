# GSV Adaptor Wire Compat (MVP)

**Status**: Implemented behind `gsv-vsss` — Fr-share extractable opening (tag 3)

## Why a separate path?

| | Phase B `AdaptorOpening` (tag 2) | GSV `GsvAdaptorOpening` (tag 3) |
|--|----------------------------------|----------------------------------|
| Secret | Independent `t` | Garbler **Fr share** |
| Label material | `SHA256(CubePhaseBLabels ‖ t)` | `SHA256(Beacon/GsvAdaptor/LabelMaterial ‖ instance ‖ Fr_BE)` |
| Roles | Engine signs; `T=t·G` | Evaluator key; commit = `share·G` |
| Endianness | n/a (hashed) | Fr **BE** on wire; LE for ShareBundle lagrange |

Do **not** treat tag 2 and tag 3 as interchangeable.

## Cube fit

GSV VSSS Assert reveals Fr shares via completed BIP340 adaptor signatures.
Beacon tag 3 packs that payload into `AssertWitnessV1` so a challenger can:

1. `extract_fr_be32()` / `extract_fr_le32()`
2. Fold with `ShareBundle` via `adaptor_share_from_gsv_fr_be` + `reconstruct_label_seed`
3. Evaluate → Disprove / Timeout (unchanged Taproot)

## Wire (AssertWitness opening tag = 3)

```text
version u8 (=3) | instance_id u32 LE
| evaluator_xonly[32] | message_hash[32] | public_inputs_hash[32]
| garbler_commit[33] | evaluator_nonce_commit[33] | evaluator_s[32 BE]
| completed_sig[64]   // BIP340 R.x || s
```

Module: [`src/phase_b/gsv_adaptor.rs`](../src/phase_b/gsv_adaptor.rs).

## Commands

```bash
export CARGO_TARGET_DIR=./target
cargo test --features gsv-vsss --no-default-features gsv_adaptor
cargo run --example gsv_adaptor --features gsv-vsss --no-default-features
```

## Not in this MVP

- `WideAdaptorInfo` (256 adaptors per input byte)
- Full VSSS C&C protocol / wide-label tables
- On-chain Tapscript that verifies the GSV evaluator `OP_CHECKSIG` path
- Replacing Phase B demos with tag 3 everywhere
