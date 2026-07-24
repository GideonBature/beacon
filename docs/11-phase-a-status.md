# Phase A – Minimal End-to-End Prototype

**Status**: Core logic implemented (simulation)

## What was built

```
src/phase_a/
├── mod.rs
├── opening.rs   ← DirectSeedOpening (Phase A extractable opening)
└── flow.rs      ← PhaseAFlow (Engine create Assert, Challenger evaluate, build Disprove / Timeout)
```

### DirectSeedOpening
- Versioned so we can later switch to adaptor openings without changing the rest of the code.
- Deterministic seed derived from the claim (for the prototype).
- `derive_label_material()` stand-in for the real wide-label expansion.

### PhaseAFlow
- `engine_create_assert` – builds the Assert template + opening + H(L_invalid)
- `challenger_evaluate` – recovers the opening, evaluates Claim Mini, returns Valid or Invalid{L*}
- `build_disprove` / `build_timeout` – produce the two possible follow-up transactions

### Tests
- Happy path (valid claim → Valid → Engine can Timeout)
- Unhappy path (inflation → Invalid → Challenger can Disprove with L*)

## What is still missing for a real regtest run

1. Actual Bitcoin transaction construction with the `bitcoin` crate
2. A running regtest node
3. Real Taproot script spending (control blocks, etc.)
4. Broadcasting and waiting for confirmations

The logical protocol is complete and can be upgraded to Phase B (adaptor) and Phase C (VSSS) without changing the connector script.

## Upgrade path remains open

- **Phase B**: replace `DirectSeedOpening` with an adaptor-signature opening.  
  The rest of `PhaseAFlow` stays the same.
- **Phase C**: add the full VSSS share reconstruction and cut-and-choose schedule.  
  Again the on-chain connector does not change.
