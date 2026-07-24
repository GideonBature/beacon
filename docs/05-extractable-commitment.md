# Extractable Commitment Scheme for Claim Mini

**Goal**: When the Engine posts Assert, any challenger must be able to extract the exact input labels needed to evaluate the garbled circuit.

We need a scheme where a valid on-chain signature / witness deterministically reveals the garbled encoding of the claim inputs.

## Recommended Starting Point: Lamport One-Time Signature

### Why Lamport first?

- Conceptually identical to the classic BitVM approach
- Extremely simple to implement and audit
- Extractability is trivial and deterministic
- Works today with pure Bitcoin Script (hashlocks)
- Perfect for a first prototype

Adaptor signatures (Schnorr) are more compact and will be preferred later, but Lamport gets us a working system faster.

### Construction (for Claim Mini)

The claim inputs that must be opened are:

```
H_old (32 B) + H_new (32 B) + total_in (8 B) + total_out (8 B) + t1..t4 (4×32 B)
= 160 + 16 = 176 bytes = 1408 bits
```

For each bit position \( i \in \{0 \dots 1407\} \):

- Garbler samples two random 32-byte labels: \( L_i^0 \) and \( L_i^1 \)
- Public key material published at setup:
  ```
  pk_i = ( H(L_i^0), H(L_i^1) )
  ```

To “sign” a concrete claim value \( x \) (the 1408-bit string):

- For every bit position the Engine reveals exactly one label:
  ```
  σ = ( L_0^{x[0]}, L_1^{x[1]}, …, L_1407^{x[1407]} )
  ```

**On-chain verification (CheckGS)**:

```
for i in 0..1407:
    assert H(σ[i]) == pk_i[ x[i] ]
```

**Extraction** (performed by any challenger):

```
labels = σ          // the revealed labels are exactly En(e, x)
```

These labels are then fed directly into the garbled circuit evaluator.

### Assert Witness Layout (Lamport version)

```
witness = {
    // the 1408 labels (one per bit)
    lamport_signature: [u8; 32] × 1408,

    // optional: the public statement in cleartext for convenience
    // (not strictly required if everything is recovered from labels)
    cleartext_claim: ClaimMini { … }
}
```

In practice we will only put the Lamport signature in the Bitcoin witness; the cleartext can be reconstructed or published off-chain alongside the Assert.

### Size Reality Check

1408 × 32 bytes ≈ 45 kB of witness data.

This is still far smaller than BitVM2’s multi-megabyte disputes, but it is not tiny.  
For the very first prototype this is acceptable. Later we can:

- Switch to Winternitz (fewer hashes)
- Move to Schnorr adaptor signatures (much more compact)
- Or hash the whole claim into a single 32-byte value and only open that (if the circuit is redesigned around a commitment)

### Alternative: Schnorr Adaptor Signatures (future)

Each digit / limb of the claim is used as the adaptor secret.  
Revealing the adapted signature lets the challenger recover the digit, which is then mapped to the corresponding pair of garbled labels (published at setup).  
This yields a much smaller on-chain footprint and is the direction we will take after the Lamport version works end-to-end.

---

**Decision for Phase 2**: Implement Lamport extractable commitment first.
