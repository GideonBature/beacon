# Cube BitVM3-style Dispute Layer – Design Overview (v0.4)

**Status**: Primary backend switched to real BitVM3 core  
**Goal**: Build Cube’s dispute layer on top of the actual BitVM3 garbled Groth16 verifier (`BitVM/garbled-snark-verifier`).

## 0. Core Decision (July 2026)

We are no longer treating a custom tiny circuit as the main path.

**Primary backend** = [BitVM/garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier)

This is the real implementation of the garbled-circuit Groth16 verifier that BitVM3 (and the Cube whitepaper) rely on.

Claim Mini is retained only as an optional lightweight fallback / testing aid.

## 1. Alignment with Cube Whitepaper

The Cube paper says:

> “Cube’s execution environment follows a **BitVM3-style** execution model in which asserted Groth16 verifier computations are transformed into **garbled-circuit verifier environments** enforceable through Bitcoin-native challenge-response disproval.”

We now follow this literally by using the official garbled SNARK verifier library.

## 2. High-Level Architecture (updated)

```
User / Watchtower                Engine                         Bitcoin
      |                            |                               |
      |                            |-- Assert (Groth16 proof +    |
      |                            |   extractable / adaptor       |
      |                            |   opening) ------------------>|
      |                            |                               |
      |<-- recover labels +        |                               |
      |    evaluate garbled        |                               |
      |    Groth16 verifier        |                               |
      |    (garbled-snark-verifier)|                               |
      |                            |                               |
      |-- Disprove (if L_invalid) -------------------------------->|
      |                            |                               |
      |                            |-- Timeout / Withdraw -------->|
      |                            |                               |
      |-- Ark / ZKTLC unilateral exit --------------------------->|
```

### Components

- **Circuit backend**: `garbled-snark-verifier` (streaming garbled Groth16 over BN254)
- **Preferred protocol variant**: VSSS + adaptor signatures (most Bitcoin-native)
- **Extractable / conditional opening**: Adaptor signatures or VSSS shares in the Assert witness
- **Fraud secret**: The invalid-output label (`L_invalid` / `L*`) produced by the garbled verifier
- **On-chain enforcement**: Exactly the same Assert / Disprove / Timeout pattern we already designed
- **Ark / ZKTLC**: Unilateral exit remains the ultimate safety net

## 3. What the Engine Asserts

In the target design the Engine asserts:

> “Here is a valid Groth16 proof that this CubeVM state transition (or batch) is correct according to CubeVM rules + relevant Bitcoin settlement rules.”

The proof is opened via the extractable / adaptor mechanism so that any challenger can feed the input labels into `garbled-snark-verifier` and evaluate the garbled verifier off-chain.

## 4. Transaction Templates (unchanged in structure)

### Assert
- Connector output with two leaves:
  - `Hashlock(H(L_invalid))` → Disprove path
  - `RelTimelock(Δ) ∧ CheckSig(Engine)` → Timeout path
- Witness contains the extractable opening (adaptor signatures / VSSS shares) of the Groth16 proof (and public inputs).

### Disprove
- Spends the Assert connector by revealing `L_invalid`.
- Extremely cheap (~100 vB range).

### Timeout / Withdraw
- Engine claims after the relative timelock if the connector was never successfully Disproved.
- Bound to the reserve / ZKTLC via pre-signed covenant emulation.

## 5. Setup

1. Garble the Groth16 verifier circuit using `garbled-snark-verifier` (with cut-and-choose).
2. Publish or distribute the garbled circuit + decoding information.
3. Derive the public key material / adaptor parameters for the extractable opening.
4. Pre-sign the Timeout/Withdraw templates that bind specific Asserts to specific reserves or ZKTLCs.
5. At least one honest party deletes toxic setup material (existential honesty).

For full Cube alignment, setup can later be scoped per participant / per ZKTLC as described in the Cube whitepaper.

## 6. Security Goals

- **Soundness**: Invalid Groth16 claims can be disputed by any honest party who evaluates the garbled verifier.
- **Completeness**: Honest Engine with a valid proof can always complete the Timeout path.
- **User safety**: Pure Ark / ZKTLC unilateral exits always remain available.
- **Economic security**: Engine bond can be slashed on successful Disprove.
- **Upgrade path**: The same transaction graph works whether the backend is the full garbled Groth16 verifier or a simpler test circuit.

## 7. Implementation Roadmap (revised)

**Phase 0–2** – Design + Claim Mini prototype + transaction templates ✅  

**Phase 3 – Switch to real backend** (current)
- [x] Adopt `garbled-snark-verifier` as primary circuit backend
- [ ] Deep study of the VSSS + adaptor protocol (`docs/gsv_vsss.md`)
- [ ] Map `L_invalid` onto our `Hashlock(H(L*))` construction
- [ ] Design the exact Assert witness format that opens the proof via adaptors / VSSS
- [ ] Prototype calling the library in Evaluate mode from our code

**Phase 4** – Bitcoin integration
- Real Assert / Disprove / Timeout transactions on regtest
- Adaptor signature scripts
- Bond / slash handling

**Phase 5** – End-to-end + Ark / ZKTLC integration

**Later** – Full CubeVM state-transition statements inside the Groth16 proofs

## 8. Open Questions

- Exact public inputs and statement that the Groth16 proof will cover for Cube v1
- Concrete adaptor / VSSS opening format that fits cleanly into a Taproot witness
- Bond size and slash distribution policy
- Whether we keep Claim Mini as an emergency lightweight mode

---

**Next concrete step**: Design the concrete Assert witness layout and Tapscript for the adaptor / VSSS opening (see `docs/09-vsss-adaptor-mapping.md`).
