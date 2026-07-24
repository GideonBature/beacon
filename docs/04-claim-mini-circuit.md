# Claim Mini – First Concrete Circuit Specification

**Status**: Ready for implementation  
**Target**: Absolute first prototype of the Cube BitVM3-style dispute layer

This is the smallest useful claim that still protects against the most dangerous form of Engine cheating (creating value or inventing state).

---

## 1. Claim Statement

**Public statement** (visible on-chain in the Assert):

> “I claim that the new state root `H_new` is the correct result of applying these 0–4 transfers to the previous state root `H_old`, and that total value leaving the system does not exceed total value entering it.”

Formally:

```
H_new = Hash( H_old || t₁ || t₂ || t₃ || t₄ )
AND
total_out ≤ total_in
```

where missing transfers are treated as the empty/zero value.

---

## 2. Inputs

### Public Inputs (appear in Assert, known to everyone)

| Name              | Size     | Description                                      |
|-------------------|----------|--------------------------------------------------|
| `H_old`           | 32 bytes | Previous state root                              |
| `H_new`           | 32 bytes | Claimed new state root                           |
| `total_in`        | 8 bytes  | Total sats entering this batch                   |
| `total_out`       | 8 bytes  | Total sats leaving this batch                    |
| `t1, t2, t3, t4`  | 32 bytes each | The (up to) 4 transfer commitments / digests  |

(We can later compress the four transfers into a single Merkle root if desired, but for the absolute first version we keep them explicit.)

### Private / Extractable Inputs

For this minimal claim the public inputs are already sufficient.  
The “private” part is simply the fact that the Engine must open the exact values that were hashed.  
In the extractable-commitment scheme the Assert witness will reveal the garbled labels corresponding to all the public inputs above.

---

## 3. Verification Logic (what the circuit must enforce)

The circuit receives the public inputs above and outputs a single bit:

- `1` (True)  → claim is valid → Engine may later timeout/Withdraw
- `0` (False) → claim is invalid → challenger obtains `L*` and can Disprove

Exact checks:

1. **Balance conservation**  
   `total_out ≤ total_in`  
   (simple 64-bit comparison)

2. **State root recomputation**  
   ```
   computed = Hash( H_old || t1 || t2 || t3 || t4 )
   ```
   where `Hash` is a fixed cryptographic hash (see §5).

3. **Equality check**  
   `computed == H_new`

4. **Output**  
   The circuit outputs `True` only if both (1) and (3) hold; otherwise `False`.

The distinguished output wire that carries this final bit is the one whose **False** label becomes `L*`.

---

## 4. Circuit Structure (high-level)

```
Inputs (all public, bit-decomposed as needed):
  H_old[256], H_new[256],
  total_in[64], total_out[64],
  t1[256], t2[256], t3[256], t4[256]

Step 1 – Balance check
  valid_balance = (total_out ≤ total_in)          // 64-bit comparator

Step 2 – Hash
  preimage = H_old || t1 || t2 || t3 || t4        // 32*5 = 160 bytes
  computed = Hash(preimage)                       // 256-bit output

Step 3 – Equality
  valid_root = (computed == H_new)                // 256-bit equality

Step 4 – Final AND
  result = valid_balance AND valid_root           // 1-bit

Output wire: result
  – True  label  → normal case
  – False label  → L*  (the fraud secret)
```

---

## 5. Choice of Hash Function

For the first prototype we have two realistic options:

| Option              | Pros                                      | Cons                              | Recommendation |
|---------------------|-------------------------------------------|-----------------------------------|----------------|
| SHA-256             | Standard, well-understood, Bitcoin-native | Relatively expensive to garble    | Acceptable     |
| Poseidon / Rescue   | Much cheaper in arithmetic circuits       | Needs SNARK-friendly environment  | Better long-term |
| Simple Blake2s or custom | Faster to implement by hand            | Less standard                     | Only for toy   |

**Decision for first prototype**: Start with **SHA-256**.  
It is conservative and matches Bitcoin culture. We can later switch the hash inside the circuit without changing any transaction templates.

---

## 6. Size Estimate (order of magnitude)

- 5 × 32-byte values to hash → SHA-256 of 160 bytes
- SHA-256 circuit in Boolean form is roughly 20k–30k gates (depending on implementation)
- Plus a 64-bit comparator and a 256-bit equality → a few thousand more gates
- **Total target**: well under 50k gates

This is still tiny compared with a full Groth16 verifier (millions of gates) and is practical to garble and evaluate on ordinary hardware.

---

## 7. How L* is Produced

1. At setup the garbler produces two labels for every wire, including the final output wire.
2. The label that corresponds to the value `False` on the final output wire is called `L*`.
3. `H(L*)` is placed in the Assert Taproot leaf as a hashlock.
4. When a challenger evaluates the circuit on an invalid claim, the final output wire evaluates to `False`, therefore the challenger obtains exactly `L*`.
5. Revealing `L*` satisfies the hashlock and spends the Assert connector → Disprove succeeds.

---

## 8. Assert Witness (what the Engine must reveal)

In the Assert transaction the Engine supplies an extractable signature / set of adaptor signatures (or Lamport signatures) that open the garbled labels of:

- `H_old`, `H_new`
- `total_in`, `total_out`
- `t1` … `t4`

Any honest challenger can recover these labels, feed them into the public garbled circuit, and obtain either the True label or `L*`.

---

## 9. Next Implementation Steps

1. Write this circuit in a concrete language (Circom for arithmetic, or a Boolean circuit DSL, or pure Rust for a first simulation).
2. Implement a simple garbling scheme (or reuse an existing privacy-free garbler).
3. Implement the extractable commitment (start with Lamport for simplicity, or Schnorr adaptors).
4. Build the Assert / Disprove transaction templates on regtest.
5. End-to-end test: honest claim → timeout succeeds; dishonest claim → Disprove succeeds with `L*`.

---

**This specification is now concrete enough to begin coding.**
