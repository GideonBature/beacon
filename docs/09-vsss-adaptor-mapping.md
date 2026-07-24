# Mapping: VSSS + Adaptor Protocol → Cube Assert / Disprove Flow

This document maps the **VSSS + adaptor signatures** protocol from  
`BitVM/garbled-snark-verifier` onto the Cube BitVM3-style dispute layer.

## 1. Roles

| garbled-snark-verifier role | Cube role              |
|-----------------------------|------------------------|
| Garbler                     | Engine (Operator)      |
| Evaluator / Challenger      | Any user or Watchtower |
| Bitcoin                     | Bitcoin (Assert / Disprove / Timeout) |

## 2. High-Level Flow (Cube view)

```
1. Setup (one-time or per epoch)
   Engine garbles n instances of the Groth16 verifier (cut-and-choose)
   and commits to wide labels + output labels (L_valid, L_invalid).

2. Assert (on-chain)
   Engine posts Assert containing:
   - Public statement / public inputs of the Groth16 proof
   - Extractable opening of one evaluation instance via adaptor signatures
     (the “instance a” in the VSSS protocol)

3. Off-chain evaluation
   Challenger:
   - Recovers the wide labels for instance a from the adaptor opening
   - Reconstructs the remaining needed labels via VSSS (using previously
     checked shares)
   - Evaluates the garbled Groth16 verifier
   - Obtains either L_valid or L_invalid

4. Disprove (if invalid)
   If L_invalid is obtained, Challenger spends the Assert connector
   by revealing L_invalid (hashlock path).

5. Timeout
   If no valid Disprove appears before the relative timelock,
   Engine completes Timeout / Withdraw.
```

## 3. Detailed Mapping of Protocol Steps

### Phase I – Setup (mostly off-chain)

**Step 1 – Committing (Engine)**

Engine generates:
- `n` garbled circuits `GC_i` of the Groth16 verifier
- Wide-label polynomials (VSSS)
- Commitments:
  - Ciphertext hashes
  - Input label commitments
  - **Output commitments**: `H(L_valid)`, `H(L_invalid)`   ← this is critical
  - Wide-label lookup table commitments
  - Share commitments

These commitments are published (or given to potential challengers) so that later openings can be verified.

**Step 2–4 – Checking, Selecting, Opening (cut-and-choose)**

Standard cut-and-choose:
- Challenger (or a committee) selects check set `C` and evaluation set `E`
- Engine opens the check instances
- Challenger verifies consistency
- One instance `a ∈ E` is designated for the adaptor opening

This can be done once per epoch or per major state, not on every Assert.

### Phase II – The Assert / Evaluation / Disprove path (the live path)

**Assert transaction (Engine posts on Bitcoin)**

The Assert witness contains the **adaptor-signature opening of the wide labels for instance `a`**.

Conceptually:

```
Assert {
  inputs:  [funding / previous connector]

  outputs: [
    Connector (Taproot)
      ├── Leaf 0:  Hashlock( H(L_invalid) )          // Disprove path
      └── Leaf 1:  RelTimelock(Δ) ∧ CheckSig(Engine) // Timeout path
  ]

  witness: {
    // public statement
    public_inputs_of_groth16_proof,
    // the adaptor opening that reveals the wide labels of instance a
    adaptor_signatures_or_completed_adaptors_for_instance_a,
    // any additional data needed to identify which garbled instance is being opened
  }
}
```

Because of the adaptor construction, anyone who sees the Assert can extract the wide labels for instance `a`.

**Off-chain evaluation (Challenger)**

1. Extract wide labels for instance `a` from the Assert witness (adaptor).
2. Using previously verified shares from the check set `C`, reconstruct the remaining labels needed for the evaluation instances via polynomial interpolation (VSSS).
3. Evaluate the corresponding garbled circuit(s) with `garbled-snark-verifier` in Evaluate mode.
4. The circuit outputs either `L_valid` or `L_invalid`.

**Disprove (if L_invalid appears)**

```
Disprove {
  input:  Assert connector (hashlock leaf)
  witness: L_invalid
  effect: spends the connector → Engine can never take the Timeout path
}
```

This is exactly the same cheap Disprove we designed earlier.  
The only difference is that `L_invalid` now comes from the real garbled Groth16 verifier instead of Claim Mini.

**Timeout / Withdraw (Engine)**

Unchanged:
- After the relative timelock, if the connector is still unspent, Engine spends it with its signature and claims the linked reserve / ZKTLC value.

## 4. Key Cryptographic Link

The most important link is:

```
output_commit = ( H(L_valid), H(L_invalid) )
```

At setup the Engine commits to both possible output labels of the garbled verifier.  
In the Assert connector we put **only** `Hashlock(H(L_invalid))`.

Therefore:

- If the evaluated proof is valid → challenger obtains `L_valid` → cannot open the hashlock.
- If the evaluated proof is invalid → challenger obtains `L_invalid` → can open the hashlock and Disprove.

This is the exact same “false-output label” idea from the BitVM3 paper and from our earlier design.

## 5. What still needs to be engineered for Cube

1. **Concrete Assert witness format**  
   Exact serialization of the adaptor opening + public inputs so that it is compact and script-friendly.

2. **Adaptor signature scripts**  
   The actual Bitcoin Script (or Tapscript) that verifies the adaptor opening inside the Assert transaction (or that makes the opening extractable).

3. **Which instance is opened**  
   Clear rule for which evaluation instance `a` is used on each Assert (or a way to indicate it).

4. **Cut-and-choose schedule**  
   How often the expensive cut-and-choose setup is re-run (per epoch, per operator, per large batch, …).

5. **Bond / slash policy**  
   What happens to the value in the Assert connector or an additional bond when Disprove succeeds.

## 6. Summary

| BitVM3 / garbled-snark-verifier concept | Cube realisation                          |
|-----------------------------------------|-------------------------------------------|
| Garbler                                 | Engine                                    |
| Evaluator                               | User / Watchtower                         |
| Wide-label opening via adaptor          | Assert witness                            |
| L_invalid                               | Preimage of the Disprove hashlock         |
| Cut-and-choose                          | Setup phase (off-chain + commitments)     |
| Evaluate mode                           | Off-chain verification by challenger      |
| Disprove transaction                    | Our existing cheap Disprove template      |

The on-chain footprint remains small.  
Almost all of the heavy work stays off-chain, exactly as BitVM3 intended.

---

**Next recommended step**:  
Design the concrete Assert witness layout (what bytes go into the witness) and the corresponding Tapscript for the adaptor / extractable opening.
