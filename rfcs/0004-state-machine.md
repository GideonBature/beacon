# RFC-0004: State Machine

- **Status:** Draft
- **Authors:** TBD
- **Created:** 2026-07-23
- **Depends on:** RFC-0001
- **See also:** RFC-0003 (events), RFC-0005 (backends)

## Abstract

This RFC defines the normative lifecycle of a Beacon Assertion: statuses,
transitions, timeouts, and terminal outcomes. Every Backend MUST preserve this
machine (RFC-0001 Invariant 5).

## Design decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Local draft before post | **Not** a protocol status | Implementation-only; consensus starts at `Asserted` |
| `Settled` | **Flag / finalization**, not a third truth value | Terminal truths are only `Accepted` or `Rejected` |
| Challenge outcome names | `Disproven` / `Upheld` (internal); public events TBD in RFC-0003 | Avoid “challenge success” ambiguity |
| Concurrent challenges | **At most one open challenge** in v1 | Simpler mock + clearer Bitcoin mapping; revisit later |

## Status

Normative statuses of an Assertion:

| Status | Meaning |
|--------|---------|
| `Asserted` | Posted; challenge window open; no challenge yet |
| `Disputing` | A challenge is open; backend dispute procedure running |
| `Accepted` | Terminal: claim stands |
| `Rejected` | Terminal: claim does not stand |

Derived predicate (not a separate status):

- `is_settled` — true iff status ∈ {`Accepted`, `Rejected`} **and** backend
  finalization side effects for that outcome have completed.

## State diagram

```text
                 assert()
                    │
                    ▼
               Asserted
               (window open)
                 │        │
     challenge() │        │ finalize() after timeout
                 │        │ with no challenge
                 ▼        ▼
            Disputing   Accepted ──► settled
                 │
                 │ dispute resolves
                 │
         ┌───────┴────────┐
         ▼                ▼
     Rejected         Accepted
         │                │
         └───────┬────────┘
                 ▼
              settled
```

Every Assertion follows exactly one path to a single terminal status.

## Transitions

### T1 — `assert` → `Asserted`

**Pre:** none (new Assertion)  
**Action:** Backend accepts Statement + Proof/Commitment, assigns `AssertionId`,
sets `deadline`, status `Asserted`.  
**Emits:** `AssertionCreated` (RFC-0003)

### T2 — `Asserted` + timeout → `Accepted`

**Pre:** status = `Asserted`, current time ≥ `deadline`, no challenge opened  
**Action:** `finalize` → `Accepted`, then settle  
**Emits:** `AssertionFinalized { outcome: Accepted }`

### T3 — `Asserted` + `challenge` → `Disputing`

**Pre:** status = `Asserted`, current time < `deadline`  
**Action:** open Challenge; status → `Disputing`  
**Emits:** `ChallengeOpened`  
**Reject:** challenge after deadline, or against settled assertion

### T4 — `Disputing` + challenger wins → `Rejected`

**Pre:** status = `Disputing`, backend determines the asserted claim is false
(e.g. `verify == false`, or valid fraud witness / BitVM3-style disproof)  
**Action:** status → `Rejected`, settle (punishment side effects)  
**Emits:** `ChallengeResolved { result: Disproven }`, then
`AssertionFinalized { outcome: Rejected }`

### T5 — `Disputing` + challenger loses → `Accepted`

**Pre:** status = `Disputing`, backend determines the challenge fails (proof
valid / disproof invalid)  
**Action:** status → `Accepted`, settle  
**Emits:** `ChallengeResolved { result: Upheld }`, then
`AssertionFinalized { outcome: Accepted }`

### T6 — `Disputing` + dispute timeout (policy)

**Pre:** status = `Disputing` longer than `dispute_deadline` (backend/protocol
parameter)  
**v1 policy (normative proposal):** treat as **challenger loses** → `Accepted`,
unless the Backend has already produced a valid disproof.  
**Rationale:** matches optimistic “asserted until proven false”; prevents
griefing by opening a challenge and stalling. Bitcoin backends MUST map this to
concrete timelock behavior in RFC-0006.  
**Open:** whether some backends require the opposite (assert bond slash on
operator stall). If needed, introduce an explicit `AbortPolicy` in RFC-0005
without changing the status set.

## Timeouts

| Parameter | Applies when | Effect |
|-----------|--------------|--------|
| `challenge_deadline` | `Asserted` | After expiry, `finalize` → `Accepted` |
| `dispute_deadline` | `Disputing` | After expiry, apply T6 |

Deadlines MUST be part of Assertion metadata (or recoverable from Backend
configuration + Assertion creation time). Exact time units (block height vs
unix time) are Backend-defined; the machine only requires a total order and
comparable “now”.

## Invariants (machine-level)

1. No transitions out of `Accepted` or `Rejected`.
2. `Rejected` and `Accepted` are mutually exclusive.
3. `challenge` is valid only from `Asserted` (v1).
4. Exactly one Challenge may be open per Assertion (v1).
5. `finalize` is idempotent after settlement: second call returns the same
   `Settlement` or a dedicated `AlreadySettled` error without changing state.

## Non-transitions

The following MUST fail:

- `challenge` on `Disputing`, `Accepted`, or `Rejected`
- `challenge` after `challenge_deadline`
- `assert` that would reuse an existing `AssertionId`
- any Backend-specific path that skips to `Accepted`/`Rejected` without
  satisfying T2–T6 (except explicit test-only hooks outside consensus)

## Mapping to API

| API (docs/traits.md) | Transitions |
|----------------------|-------------|
| `assert` | T1 |
| `challenge` | T3 |
| `finalize` | T2, T4, T5, T6 |

Backends MAY run dispute resolution inside `challenge` (synchronous mock) or
defer completion until `finalize` / a block tick (Bitcoin). Status observed by
applications MUST still match this machine.

## Open questions

1. Confirm v1 single-challenge limit vs allow parallel challengers.
2. Confirm T6 abort policy (optimistic default vs configurable).
3. Whether `Asserted` should be split into `Asserted` + `Challenging` as in
   earlier informal diagrams—or keep two statuses for clarity (current choice:
   four statuses total).
4. Bond / stake state: tracked inside Backend only, or mirrored in Assertion
   metadata?
