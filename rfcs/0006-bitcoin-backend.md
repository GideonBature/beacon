# RFC-0006: Bitcoin Backend

- **Status:** Draft (templates + simulated journal)
- **Depends on:** RFC-0005, RFC-0004
- **Implementation:** `crates/beacon-bitcoin`

## Intent

Map RFC-0004 transitions onto Bitcoin transactions and, later, BitVM3-style
disprovable verification (garbled verifier, label secrets, hashlocks/timelocks).

This RFC MUST NOT redefine the Assertion lifecycle. It only specifies how a
Bitcoin `DisputeBackend` realizes it.

## Current implementation

`beacon-bitcoin` implements `DisputeBackend` by:

1. Delegating lifecycle + `Verifiable::check` to the mock engine.
2. Recording a simulated transaction journal with structured **templates**.

### Journal mapping

| Protocol | `TxKind` | `ScriptIntent` |
|----------|----------|----------------|
| T1 Asserted | `Assert` | `AssertCommit { challenge_deadline }` |
| T3 Disputing | `Challenge` | `ChallengeOpen { challenger, challenge_deadline }` |
| Evidence invalid (sync) | `Disprove` | `DisproveHashlock { challenger }` |
| T2 / T5 Accepted | `Withdraw` | `WithdrawTimeout { unlocked_at }` |
| T4 Rejected | `Punish` | `PunishBond { challenger }` |

### Template fields

Each [`TxTemplate`](../crates/beacon-bitcoin/src/template.rs) carries:

- `assertion_id`
- `intent` (`ScriptIntent`)
- `spends` (previous tip txid, if any)
- `value_sats` (bond placeholder; configurable via `BitcoinBackend::with_bond`)

Journal entries also include deterministic `txid`, optional `locktime`, and
`prev_txid`.

`ScriptIntent` is the seam where real Taproot / CSV / CLTV / hashlock Script
(and later BitVM3-style secrets) will plug in — without changing
`DisputeBackend`.

## Non-goals (still)

- Real Bitcoin transactions / PSBTs / networking
- Choosing a garbling scheme
- Bridge or Cube application flows
- Wallet / mempool integration

## Anticipated real mapping

| `ScriptIntent` | On-chain direction |
|----------------|--------------------|
| `AssertCommit` | Taproot commit + absolute timelock to withdraw |
| `ChallengeOpen` | Challenge bond / relative lock race |
| `DisproveHashlock` | Hashlock or garble-secret spend (BitVM3-style) |
| `WithdrawTimeout` | Operator withdraw after challenge window |
| `PunishBond` | Slash assertor bond to challenger |

## Open

- Compile templates to concrete Taproot scripts / PSBTs
- Replace mock `check()` with on-chain-enforceable dispute artifacts
- Async challenge resolution (separate Challenge vs Disprove broadcasts)
- Bond economics beyond `value_sats` placeholders
