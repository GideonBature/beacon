# Backend Switch: Claim Mini → Real BitVM3 Garbled Groth16

**Date**: 24 July 2026  
**Decision**: Primary circuit backend is now `BitVM/garbled-snark-verifier`.

## Why the switch

1. The library is the actual implementation of the BitVM3 core.
2. The Cube whitepaper explicitly calls for a BitVM3-style garbled Groth16 verifier.
3. Performance is already strong (streaming, ~57 M gates/s, low memory).
4. Continuing with only a tiny custom circuit would diverge from both BitVM3 and the Cube design.

## What stays the same

- Assert / Disprove / Timeout transaction structure
- Use of a false-output / invalid label (`L*`) as the fraud proof
- Hashlock + relative timelock connector pattern
- Ark / ZKTLC as the unilateral-exit safety net
- Existential honesty setup assumption

## What changes

| Aspect                    | Before (Claim Mini)              | After (garbled-snark-verifier)          |
|---------------------------|----------------------------------|-----------------------------------------|
| Circuit                   | Tiny custom hash + balance check | Full streaming garbled Groth16 verifier |
| Statement                 | Limited claims                   | Real CubeVM state-transition proofs     |
| Opening mechanism         | Lamport (simple)                 | VSSS + adaptor signatures (preferred)   |
| Off-chain cost            | Very low                         | Higher (but still practical)            |
| Alignment with whitepaper | Partial                          | Direct                                  |

## Claim Mini status

Kept in the repository as:

- A simple test / simulation target
- A possible emergency lightweight mode
- A pedagogical example of the overall flow

It is no longer the production path.

## Implementation status

The pluggable [`CircuitBackend`](14-circuit-backend.md) trait is in tree:

- `ClaimMiniBackend` — Phase A (live)
- `GarbledSnarkBackend` — stand-in with GSV integration contract; real crate not linked yet

`H(L_invalid) = SHA256(L*)` for the Taproot hashlock.

## Immediate next engineering tasks

1. Study `docs/gsv_vsss.md` inside the garbled-snark-verifier repository in detail.
2. Link `garbled-snark-verifier` and replace the stand-in `evaluate` body.
3. Define the exact public inputs + statement that Cube’s Groth16 proofs will cover in v1.
4. Design the Assert witness format that opens the proof via the VSSS / adaptor mechanism.
5. Real Taproot signatures + regtest broadcast.

Once those are clear, we can move to real regtest transactions.
