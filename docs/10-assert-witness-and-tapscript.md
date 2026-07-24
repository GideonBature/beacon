# Assert Witness Layout & Tapscript Design
## Cube BitVM3-style Dispute Layer (using garbled-snark-verifier)

**Goal**: Define exactly what bytes go into the Assert transaction and how the locking script enforces the BitVM3-style flow.

---

## 1. Design Principles for the Witness

1. **Extractability** – Any third party who sees the Assert must be able to recover the wide labels of the designated evaluation instance (`a`) so they can run the garbled verifier.
2. **Minimal on-chain size** – Keep the witness as compact as practical.
3. **Simple Disprove path** – Disprove must remain a pure hashlock of `L_invalid` (no complex scripts).
4. **Compatibility** – Work with the VSSS + adaptor protocol from `garbled-snark-verifier`.
5. **Upgradeability** – The same connector pattern must later accept richer openings if needed.

---

## 2. Assert Transaction Structure (logical)

```text
Assert
├── Input(s)
│     └── Funding UTXO / previous connector
│
├── Output 0 – Connector (Taproot)
│     ├── Leaf 0 (Disprove):   OP_SHA256 <H(L_invalid)> OP_EQUALVERIFY OP_TRUE
│     └── Leaf 1 (Timeout):    <Δ> OP_CHECKSEQUENCEVERIFY OP_DROP
│                               <Engine_pubkey> OP_CHECKSIG
│
└── Witness
      ├── Internal key path (or script path spend metadata)
      └── Script-path witness for the opening leaf (see §3)
```

The connector is the only output that matters for the dispute logic.  
Additional outputs (change, fees, etc.) can exist but are irrelevant to the protocol.

---

## 3. Concrete Assert Witness Layout

We define two layers:

### 3.1 Public Statement (always visible)

These values are either placed in an `OP_RETURN` / annex or reconstructed from the opened labels.  
For clarity we treat them as part of the logical witness:

```text
public_statement = {
  version:            u8,                 // protocol version
  instance_id:        u32,                // which evaluation instance “a” is being opened
  public_inputs_hash: [u8; 32],           // hash of the Groth16 public inputs
  claim_id:           [u8; 32],           // optional: identifier of the Cube state transition
}
```

### 3.2 Extractable Opening (the critical part)

This is the data that lets a challenger recover the wide labels of instance `a`.

**Recommended first version – Adaptor Signature Opening**

```text
adaptor_opening = {
  // One or more adaptor signatures that, once completed,
  // reveal the wide-label material for instance a.
  //
  // Concrete encoding (illustrative):
  num_adaptors:       u16,
  adaptors: [
    {
      adaptor_point:   [u8; 33],          // compressed point T
      adapted_sig:     [u8; 64],          // s', R  (or whatever the adaptor scheme uses)
      // optional: encrypted seed or share that becomes decryptable
      // once the adaptor secret is recovered
    }
  ],

  // After the adaptor secret is recovered, the challenger can decrypt
  // or derive the wide labels.  For the first implementation we can
  // also include a compact encryption of the labels under a key that
  // is the adaptor secret.
  encrypted_wide_labels:  bytes,          // AES-GCM or similar under adaptor secret
  encryption_nonce:       [u8; 12],
}
```

**Alternative simpler (but larger) version – Direct Reveal with Lamport / Winternitz**

If adaptor complexity is too high for the first prototype, we can fall back to a one-time signature that simply reveals the wide labels (or a seed that expands to them). This is larger but easier to implement and still works with the same connector.

```text
direct_opening = {
  seed_or_labels: bytes,                  // the actual wide-label material
  // optional integrity MAC / signature so the Engine cannot open inconsistently
}
```

**Decision for first implementation**  
Start with the **direct opening** (simpler) while keeping the witness layout ready for adaptor signatures.  
Later replace the opening with the real VSSS + adaptor construction from the library.

---

## 4. Tapscript for the Connector

### Leaf 0 – Disprove (hashlock)

```text
OP_SHA256
<H(L_invalid)>          // 32-byte commitment made at setup
OP_EQUALVERIFY
OP_TRUE                 // or a small clean-up / anyone-can-spend
```

Witness for this leaf:

```text
<L_invalid>             // 32 bytes
```

This is intentionally the simplest possible script.  
Any party that obtains `L_invalid` from evaluating the garbled verifier can spend it.

### Leaf 1 – Timeout

```text
<Δ>                     // relative locktime (e.g. 144 blocks)
OP_CHECKSEQUENCEVERIFY
OP_DROP
<Engine_pubkey>
OP_CHECKSIG
```

Witness:

```text
<Engine_signature>
```

---

## 5. How a Challenger Uses the Assert

1. Parse the Assert transaction and extract the opening (adaptor or direct).
2. Recover the wide labels for the designated instance `a`.
3. (If using full VSSS) reconstruct any missing labels from previously verified shares.
4. Feed the labels + the public garbled circuit into `garbled-snark-verifier` in **Evaluate** mode.
5. The library returns either `L_valid` or `L_invalid`.
6. If `L_invalid`:
   - Construct Disprove transaction spending the connector with the hashlock leaf.
   - Broadcast it.
7. If `L_valid` (or evaluation is never performed):
   - Do nothing. After `Δ` blocks the Engine can take the Timeout path.

---

## 6. Setup Material That Must Be Published

Before any Assert can be posted, the following must be known to potential challengers:

| Item                              | Purpose                                      |
|-----------------------------------|----------------------------------------------|
| Garbled circuits (or seeds)       | So the evaluator can run Evaluate mode       |
| `H(L_valid)`, `H(L_invalid)`      | So the Disprove hashlock can be verified     |
| Wide-label commitment material    | For VSSS consistency checks                  |
| Cut-and-choose openings (check set) | To ensure the circuits were generated honestly |
| Mapping `instance_id → circuit`   | So the challenger knows which GC to evaluate |

This material can be published on a bulletin board, IPFS, or distributed directly to watchtowers.

---

## 7. Size Estimates (order of magnitude)

| Component                    | Estimated size          | Notes                              |
|-----------------------------|-------------------------|------------------------------------|
| Public statement            | ~100 bytes              | Fixed                              |
| Direct opening (seed)       | 32–64 bytes             | Smallest practical                 |
| Adaptor opening             | a few hundred bytes     | Depends on number of adaptors      |
| Full wide-label reveal      | several kB              | Only if we reveal everything       |
| Disprove witness            | 32 bytes + control block | Extremely cheap                    |

The dominant cost on-chain is the Assert itself; Disprove stays negligible.

---

## 8. Implementation Phases for the Witness

**Phase A – Minimal viable (recommended next)**  
- Use a direct seed opening (32–64 bytes).  
- Engine commits to `H(L_invalid)` at setup.  
- Assert simply reveals a seed that expands to the wide labels of instance `a`.  
- Challenger evaluates and, if necessary, Disproves with `L_invalid`.

**Phase B – Real adaptor**  
- Replace the direct seed with the adaptor-signature construction from `garbled-snark-verifier`.  
- Same connector script; only the witness interpretation changes.

**Phase C – Full VSSS**  
- Add the polynomial share reconstruction and the full cut-and-choose schedule.

---

## 9. Summary of the On-Chain Contract

```text
Connector locking script (Taproot)

Leaf 0 (Disprove):
  SHA256(L_invalid) == <committed H(L_invalid)>

Leaf 1 (Timeout):
  after Δ blocks + Engine signature
```

Everything else (Groth16 proof, wide labels, VSSS shares, adaptor secrets) lives in the **witness** of Assert or is recovered off-chain.  
This keeps the on-chain logic minimal while still enforcing the full BitVM3-style security.

---

**Next concrete step after this document**  
Implement a minimal version of Phase A (direct seed opening + Claim Mini or a stub garbled verifier) on regtest so we can see the full Assert → Evaluate → Disprove / Timeout flow working end-to-end.
