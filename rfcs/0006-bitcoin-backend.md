# RFC-0006: Bitcoin Backend

- **Status:** Placeholder
- **Depends on:** RFC-0005, RFC-0004
- **Phase:** 5–6 (after Mock)

## Intent

Map RFC-0004 transitions onto Bitcoin transactions and, later, BitVM3-style
disprovable verification (garbled verifier, label secrets, hashlocks/timelocks).

This RFC MUST NOT redefine the Assertion lifecycle. It only specifies how a
Bitcoin `DisputeBackend` realizes it.

## Non-goals for now

- Normative tx templates (until Phase 0–2 freeze core protocol)
- Choosing a specific garbling scheme
- Bridge or Cube application flows

## Anticipated mapping (informative)

| RFC-0004 | Bitcoin-shaped analogue |
|----------|-------------------------|
| T1 Asserted | Assert / commit transaction |
| T3 Disputing | Challenge transaction |
| T4 Rejected | Disprove / punish path |
| T2 / T5 Accepted | Timeout / withdraw path |
| T6 dispute timeout | Timelock resolution |

## Open

Full write-up after Mock semantics and state machine open questions are closed.
