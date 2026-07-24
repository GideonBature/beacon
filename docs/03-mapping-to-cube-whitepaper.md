# Mapping: Cube Whitepaper ↔ Our BitVM3-style Design

This document shows how our implementation plan directly realises the architecture described in the Cube whitepaper.

## Key Quotes from Cube Whitepaper

1.  
> “Cube’s execution environment follows a **BitVM3-style** execution model in which asserted Groth16 verifier computations are transformed into **garbled-circuit verifier environments** enforceable through Bitcoin-native challenge-response disproval.”

**Our realisation**:  
We implement exactly this pattern. In v1 the “verifier computation” is a tiny circuit for limited claims. Later it becomes the full garbled Groth16 verifier of CubeVM transitions. The surrounding Assert / Disprove / Timeout machinery stays identical.

2.  
> “If evaluation yields an invalid result, the garbled verifier derives the **disproval secret** corresponding to the failing output-wire label, allowing the participant to trigger the associated punitive settlement path through the committed Bitcoin hashlock condition.”

**Our realisation**:  
This is precisely our `L*` (false-output label) + `Hashlock(H(L*))` construction.

3.  
> “At its core, a ZKTLC is a timeout-tree virtual output carrying a zero-knowledge computation assertion enforceable through BitVM disproval.”

**Our realisation**:  
The dispute layer we are building is the “BitVM disproval” part of the ZKTLC. The timeout-tree / Ark unilateral exit remains the ownership and forced-exit part.

4.  
> Setup is scoped per participant… each participant performs an individual setup ceremony directly together with the Engine… controls destruction of their own toxic-waste material.

**Our realisation**:  
For the full Cube target we will support per-participant (or per-ZKTLC) setup. For the practical v1 we can start with a simpler shared or Engine-assisted setup while keeping the same security model (existential honesty).

## Summary of Alignment

| Cube Whitepaper Concept              | Our Design Element                          | Status in v1                  |
|--------------------------------------|---------------------------------------------|-------------------------------|
| BitVM3-style garbled verifier        | Garbled circuit + extractable commitment    | Tiny circuit first            |
| Disproval secret / failing label     | `L*` + Hashlock(H(L*))                      | Fully implemented             |
| Assert → off-chain eval → Disprove   | Exact same flow                             | Fully implemented             |
| ZKTLC (timeout tree + computation)   | Ark/timeout-tree + our dispute layer        | Dispute layer first           |
| Full CubeVM state-transition proof   | Future replacement of the tiny circuit      | Upgrade path reserved         |
| Per-participant setup / toxic waste  | Supported by architecture                   | Simplified for first prototype|

## Conclusion

We are not building a generic “pseudo” system that diverges from Cube.  
We are building the **BitVM3-style dispute layer that the Cube whitepaper itself calls for**, starting with a restricted but immediately usable set of claims, and with a clean path to the full garbled Groth16 CubeVM verifier.
