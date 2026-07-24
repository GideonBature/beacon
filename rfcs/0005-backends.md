# RFC-0005: Backend Interface

- **Status:** Draft
- **Authors:** TBD
- **Created:** 2026-07-23
- **Depends on:** RFC-0001, RFC-0002, RFC-0004
- **See also:** [docs/traits.md](../docs/traits.md), RFC-0006

## Abstract

This RFC defines the `DisputeBackend` contract and the semantics of the
reference **Mock** backend. All backends—including future Bitcoin /
BitVM3-style ones—MUST preserve the RFC-0004 state machine.

## Backend kinds

| Kind | Role | Phase |
|------|------|-------|
| **Mock** | Reference lifecycle; software `verify` | Phase 2 |
| **Software** | Production-shaped but off-chain enforcement | optional |
| **Bitcoin** | On-chain assert/challenge/settle | RFC-0006 |
| **Future** | Covenants, alternate dispute crypto, etc. | later |

“Software” and “Mock” may share an implementation initially. The Mock backend
is normative as the *reference behavior* for tests and for validating RFCs.

## DisputeBackend contract

Capabilities (see also docs/traits.md):

```text
DisputeBackend
  associated: Statement, Evidence: Verifiable, AssertionId, ChallengerId

  assert(evidence, timeout) -> AssertionId
  challenge(assertion_id, challenger) -> ()
  finalize(assertion_id) -> Settlement
```

### Requirements

1. **Lifecycle preservation (RFC-0001 Invariant 5).** Status transitions MUST
   match RFC-0004.
2. **No application types.** Interfaces MUST NOT mention CubeVM, bridges, or
   wallets.
3. **Proof-system opacity (RFC-0001 Invariant 6).** Backends consume
   `Verifiable` evidence only. They MUST NOT require Groth16, SP1, Halo2,
   Plonky, or RISC Zero types in the generic interface.
4. **Settlement exclusivity.** `finalize` yields exactly one of `Accepted` or
   `Rejected` per Assertion.
5. **Side effects localized.** Bonds, punishment, and Bitcoin transactions are
   Backend-private consequences of settlement—not separate lifecycle statuses.

### Suggested errors

```text
NotFound
InvalidState
ChallengeWindowClosed
AlreadySettled
MalformedAssertion
DisputePending          // finalize called too early
BackendFailure
```

## Mock backend (reference design)

### Goal

Executable specification of RFC-0004 without Bitcoin, garbling, or networking.

### Storage (conceptual)

```text
MockAssertion {
  id: AssertionId
  evidence: Evidence          // Verifiable
  commitment: Commitment
  challenge_deadline: Time
  dispute_deadline: Option<Time>
  status: Status
  challenge: Option<MockChallenge>
}

MockChallenge {
  opened_at: Time
  result: Option<Disproven | Upheld>
}
```

### Behavior

#### `assert`

1. Compute commitment binding to `evidence`.
2. Insert `MockAssertion` with status `Asserted` and configured
   `challenge_deadline`.
3. Return `id`.
4. Emit `AssertionCreated`.

Does **not** require evidence to pass `check()` at assert time (optimistic).

#### `challenge`

1. Reject if status ≠ `Asserted` or now ≥ `challenge_deadline`.
2. Set status `Disputing`; set `dispute_deadline`.
3. Run `evidence.check()` synchronously:
   - `false` → record `Disproven` (challenger wins once finalized)
   - `true` → record `Upheld` (assertion wins once finalized)
4. Emit `ChallengeOpened` and `ChallengeResolved`.

v1 mock MAY resolve inside `challenge`. A Bitcoin backend will usually defer
resolution; applications should treat `Disputing` as waiting until `finalize`
or an equivalent tick when using async backends.

#### `finalize`

| Condition | Result |
|-----------|--------|
| `Asserted` and now ≥ `challenge_deadline` | `Accepted` |
| `Disputing` and result `Disproven` | `Rejected` |
| `Disputing` and result `Upheld` | `Accepted` |
| `Disputing`, no result yet, now ≥ `dispute_deadline` | T6 → `Accepted` (RFC-0004) |
| Already settled | `AlreadySettled` / same `Settlement` |
| Otherwise | `DisputePending` or `InvalidState` |

On first successful finalize: set terminal status, mark settled, emit
`AssertionFinalized`.

### Mock “secret” (optional BitVM3 stand-in)

For later exercises that mimic fraud-witness reveal without garbling:

```text
if evidence.check() == false:
    mock_secret = H(evidence_bytes)
else:
    no secret
```

Punishment in the mock is recording `Rejected` (and optional counters). Real
hashlock spend paths belong in RFC-0006. The public API MUST NOT require
callers to handle `mock_secret` unless using a Bitcoin-shaped backend trait
extension.

## Software vs Mock

| | Mock | Software |
|---|------|----------|
| Purpose | Spec + tests | Off-chain demo / staging |
| Clocks | Injected / logical | Real time or blocks |
| ProofSystem | Often trivial or Groth16 | Usually real verifier |
| Enforcement | In-memory | Still off-chain |

## Path to Bitcoin (non-normative)

```text
MockBackend.verify()
        │
        ▼
BitcoinBackend dispute protocol
        │
        ▼
BitVM3-style garbled verifier + hashlocks
```

Only the Backend implementation changes. RFC-0006 specifies the Bitcoin mapping
of T1–T6 (Assert / Challenge / Resolve / Timeout transactions).

## Open questions

1. Should `challenge` be split into `open_challenge` + `resolve_challenge` for
   all backends, with Mock implementing resolve immediately?
2. Multi-challenger and challenger bonds: v2 only?
3. How much of Commitment / Proof blob availability is Backend vs application
   responsibility?
