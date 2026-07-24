# Limited Claims Specification – Cube BitVM3-style v1

These claims are the **practical starting point**.  
They keep the circuit tiny so we can ship a working dispute layer quickly, while the overall architecture remains identical to the full BitVM3-style model described in the Cube whitepaper.

## Primary Claim for First Prototype: State Root + Balance

### Statement

Public inputs:
- `H_old`             : 32-byte previous state root
- `H_new`             : 32-byte claimed new state root
- `total_in`          : 8-byte total value entering the batch (sats)
- `total_out`         : 8-byte total value leaving the batch (sats)
- `batch_commitment`  : 32-byte commitment to the list of transfers

Private / extractable inputs (known to Engine, recoverable by any challenger from the Assert witness):
- The actual list of transfers (or Merkle proof + leaves)
- Any intermediate values needed for the hash chain

### Verification Logic (what the circuit must check)

1. `total_out ≤ total_in`                          → no inflation
2. Recompute the new state root from `H_old` + the batch
3. Recomputed root equals the claimed `H_new`
4. `batch_commitment` correctly commits to the transfers used in the recomputation

### Recommended Ultra-Minimal Variant (for absolute first prototype)

**Claim Mini**:
- Balance conservation only + a short incremental hash-chain of ≤ 4 transfers.
- `H_new = Hash(H_old || t1 || t2 || t3 || t4)`
- Circuit needs only a handful of hash invocations + comparisons.

This is the recommended starting point because it is small enough to garble and evaluate easily while still giving real protection against the most dangerous class of Engine cheating (creating value out of thin air or inventing fake state).

## Claim C: Authorized Exit

Public inputs:
- User identifier / pubkey
- Amount `v`
- Previous and new user balance commitments

Circuit checks:
- Exit is authorized
- New balance = old balance – `v`
- `v > 0` and does not exceed old balance

This claim is even smaller and can be added early.

## Future Claims (aligned with Cube Whitepaper)

Once the basic Assert / Disprove machinery is working, we replace (or complement) the tiny circuit with:

- Full Groth16 proof that a CubeVM state transition is valid according to CubeVM rules + relevant Bitcoin settlement rules.
- The Groth16 **verifier itself** is then garbled (exactly the BitVM3-style model the Cube paper describes).

The transaction templates, connector pattern, and fraud-secret mechanism stay the same. Only the circuit changes.

---

**Decision for next step**:  
We recommend starting with **Claim Mini** (balance + ≤ 4-transfer hash chain).  
It is small, concrete, and still useful. We can expand it once the surrounding infrastructure works.
