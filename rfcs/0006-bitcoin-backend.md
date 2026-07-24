# RFC-0006: Bitcoin Backend

- **Status:** Draft (skeleton)
- **Depends on:** RFC-0005, RFC-0004
- **Implementation:** `crates/beacon-bitcoin` (simulated journal)

## Intent

Map RFC-0004 transitions onto Bitcoin transactions and, later, BitVM3-style
disprovable verification (garbled verifier, label secrets, hashlocks/timelocks).

This RFC MUST NOT redefine the Assertion lifecycle. It only specifies how a
Bitcoin `DisputeBackend` realizes it.

## Skeleton (current)

`beacon-bitcoin` implements `DisputeBackend` by:

1. Delegating lifecycle + `Verifiable::check` to the mock engine (same tests).
2. Appending a **simulated** transaction journal:

| Protocol | `TxKind` |
|----------|----------|
| T1 Asserted | `Assert` |
| T3 Disputing | `Challenge` |
| Evidence invalid (sync) | `Disprove` |
| T2 / T5 Accepted | `Withdraw` |
| T4 Rejected | `Punish` |

No real Bitcoin, scripts, or BitVM3 yet.

## Non-goals (still)

- Normative tx templates / PSBTs
- Choosing a garbling scheme
- Bridge or Cube application flows
- Network / mempool / wallet integration

## Anticipated real mapping

| RFC-0004 | On-chain analogue |
|----------|-------------------|
| T1 Asserted | Assert / commit transaction |
| T3 Disputing | Challenge transaction |
| T4 Rejected | Disprove / punish path |
| T2 / T5 Accepted | Timeout / withdraw path |
| T6 dispute timeout | Timelock resolution |

## Open

- Replace mock `check()` with BitVM3-style dispute artifacts
- Concrete Taproot / hashlock / timelock templates
- Whether `Disprove` is a separate broadcast from `Challenge` in async settings
