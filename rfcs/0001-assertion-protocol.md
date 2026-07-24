# RFC-0001: Assertion Protocol

| Field | Value |
|-------|-------|
| **Title** | Assertion Protocol |
| **Status** | Draft |
| **Authors** | TBD |
| **Created** | 2026-07-23 |
| **Category** | Standards Track (protocol) |
| **Updates** | — |

## Abstract

Beacon defines a protocol for optimistic, challenge-based verification of
cryptographic claims. A party asserts that a Statement is true. Other parties
may challenge that Assertion. Settlement yields exactly one terminal outcome:
Accepted or Rejected.

Rust is the first implementation language, not the definition. Compatible
implementations (`beacon-rust`, `beacon-go`, `beacon-ts`, …) MUST follow this
protocol.

## Philosophy

> **Beacon specifies *what* an assertion protocol must do, not *how* a backend
> performs verification.**

A software backend, a BitVM3-style Bitcoin backend, or a future covenant-enabled
backend MUST implement the same assertion lifecycle. Applications MUST interact
only with Assertions, Challenges, and Settlements—not with backend internals.

Beacon starts from:

```text
Assertion → Challenge → Settlement
```

not from:

```text
Bitcoin → Bridge → Proof
```

Bitcoin is one Backend (RFC-0006). BitVM3-style techniques belong there—not in
this RFC.

## Motivation

Modern cryptographic systems frequently require optimistic verification in which
one party asserts the correctness of a computation while other parties are given
an opportunity to dispute that claim. Existing implementations tightly couple
the dispute mechanism to a specific application (such as a bridge or rollup) or
to a specific verification technology, making reuse difficult.

Beacon defines a generic assertion protocol that separates assertion, challenge,
and settlement from any specific application or proof system.

This RFC deliberately names neither Bitcoin nor any particular application.
Those are consumers or backends of the protocol, not its definition.

**First driver (non-normative):** Cube’s dispute requirements motivate the
initial reference implementation. The protocol itself remains application-
agnostic; see `docs/architecture.md` for Cube-driven extraction discipline.

## Goals

Beacon has exactly five goals.

### Goal 1 — Backend Agnostic

The lifecycle MUST be expressible without reference to a specific settlement or
dispute technology.

### Goal 2 — Proof System Agnostic

The protocol MUST NOT require a particular proof system. Concrete proof systems
are adapters behind the Verifiable / Proof interface (RFC-0002).

### Goal 3 — Deterministic Lifecycle

Every Assertion follows the same lifecycle. Applications MUST be able to reason
about Status transitions without backend-specific exceptions.

### Goal 4 — Application Agnostic

Beacon MUST NOT encode application semantics. Cube (or any other system) is a
consumer of Beacon, not part of its definition.

### Goal 5 — Composable

Applications MUST be able to build higher-level protocols on Assertions—for
example by binding application-level funds or exits to Settlement outcomes—
without modifying the core lifecycle.

## Definitions

These terms are normative. Prefer this closed vocabulary in this RFC.

| Term | Meaning |
|------|---------|
| **Statement** | A public claim whose correctness may be asserted. |
| **Witness** | Private or auxiliary data used when producing a Proof. |
| **Proof** | Evidence that a Statement is true. At the protocol boundary this is Verifiable material (RFC-0002), not a named SNARK type. |
| **Assertion** | The central protocol object: a public claim that a Statement is true, subject to challenge until a Deadline, then Settled. |
| **Challenge** | An active dispute against exactly one Assertion. |
| **Settlement** | Irreversible conclusion of an Assertion as Accepted or Rejected, including backend enforcement side effects. |
| **Verifier** | A procedure or mechanism that checks Proof against Statement (software check or backend dispute protocol). |
| **Backend** | An implementation of verification and enforcement that realizes this lifecycle. |
| **Timeout** | A deadline after which a challenge window (or dispute) closes per the state machine. |
| **Status** | The lifecycle state of an Assertion. |

**Challenger** (role): a party who opens a Challenge. Not a separate protocol
object beyond identity metadata on Challenge.

## Central object: Assertion

Everything revolves around **Assertion**.

Not Proof. Not Verifier. Not Challenge. Everything else references an Assertion.

```text
Assertion {
    id:        AssertionId
    statement: Statement
    proof:     Proof          // or Commitment to Proof; see notes
    backend:   BackendId
    deadline:  Timeout
    status:    Status
}
```

Notes:

1. **Proof field.** Optimistic backends MAY store a binding Commitment at assert
   time and keep the full Proof off the Assertion record until challenge. The
   logical assertion still *claims* a Statement with associated evidence.
2. **Draft.** Preparing an Assertion before post is implementation-local. It is
   not a consensus-relevant Status.
3. **Challenge** and **Settlement** MUST reference `AssertionId`.

## Protocol

```text
               Statement
                    │
                    ▼
                Proof
                    │
                    ▼
               Assertion
                    │
        ┌───────────┴───────────┐
        │                       │
        ▼                       ▼
 No Challenge             Challenge
 (window expires)               │
        │                       ▼
        │                  Verification
        │                       │
        │            ┌──────────┴──────────┐
        │            ▼                     ▼
        │     Challenge fails        Challenge succeeds
        │     (proof holds)          (proof fails)
        │            │                     │
        ▼            ▼                     ▼
             Accepted                  Rejected
                    │                     │
                    └──────────┬──────────┘
                               ▼
                          Settlement
```

Steps:

1. An asserter posts an Assertion (Statement, Proof/Commitment, Backend,
   Deadline).
2. During the challenge window, an eligible Challenger MAY open a Challenge.
3. If no successful Challenge occurs before the Deadline, the Assertion is
   Accepted and Settled.
4. If a Challenge is opened, the Backend runs verification / dispute.
5. Challenge fails → Accepted and Settled. Challenge succeeds → Rejected and
   Settled.

That is the entire engine. Backend technology only implements Verification.

## State Machine

Normative Status values and transition rules: **RFC-0004**.

Informative diagram (maps to RFC-0004):

```text
            [Draft]                    ← local only; not a protocol Status
              │
              ▼
          Asserted                     ← challenge window open
              │
      ┌───────┴───────┐
      │               │
      ▼               ▼
 No Challenge   Challenge Opened
 (timeout)            │
      │               ▼
      │        Verification Running     ← Status: Disputing
      │               │
      │      ┌────────┴────────┐
      │      ▼                 ▼
      │ Challenge Success  Challenge Failed
      │ (challenger wins)  (assertion upheld)
      │      │                 │
      ▼      ▼                 ▼
  Accepted  Rejected       Accepted
      │      │                 │
      └──────┴────────┬────────┘
                     ▼
                 Settled               ← finalization, not a third truth value
```

Every Assertion follows exactly one path to a single terminal outcome
(`Accepted` or `Rejected`). No exceptions. No Backend-specific shortcuts.

| Informative label | Normative (RFC-0004) |
|-------------------|----------------------|
| Draft | not protocol-visible |
| Asserted / challenge window | `Asserted` |
| Challenge opened / verification | `Disputing` |
| Accepted / Rejected | terminal Status |
| Settled | finalization complete for that terminal Status |

Challenge outcome naming in events uses `Disproven` / `Upheld` (RFC-0003) to
avoid ambiguous “success” without a subject.

## Events

Normative schemas: **RFC-0003**.

| Event | Meaning |
|-------|---------|
| `AssertionCreated` | Assertion posted; window open |
| `ChallengeOpened` | Challenge begun |
| `ChallengeResolved` | `Disproven` or `Upheld` |
| `AssertionFinalized` | Settled as `Accepted` or `Rejected` |

Informal aliases `ChallengeSucceeded` / `ChallengeFailed` MUST NOT be used in
normative text (subject ambiguity).

## Invariants

### Invariant 1 — Single settlement

An Assertion can only be settled once.

### Invariant 2 — Challenge ownership

Every Challenge belongs to exactly one Assertion.

### Invariant 3 — Monotonic lifecycle

A Settled Assertion can never return to an earlier state.

### Invariant 4 — Exclusive terminal outcome

Exactly one terminal truth value exists: `Accepted` **or** `Rejected`.
Never both. Never neither.

### Invariant 5 — Backend lifecycle preservation

Backends MAY extend how verification is performed. They MUST NOT change the
lifecycle observed by applications.

This guarantees that a Software Backend and a BitVM3-style Backend behave
identically from the application’s perspective with respect to Assertion
Status.

### Invariant 6 — Proof-system opacity

Core protocol types MUST NOT require a specific proof system. Evidence enters
as Proof / Verifiable (RFC-0002).

### Invariant 7 — Successful challenge invalidates

If a Challenge succeeds (evidence shows the Assertion false), the terminal
outcome MUST be `Rejected`.

## Failure Cases

Resolutions MUST preserve the invariants. Detailed rules: RFC-0004, RFC-0005.

Non-exhaustive:

- Assertion posted with malformed Statement or Proof
- Challenge opened after Deadline
- Challenge opened against a Settled Assertion
- Backend verification abort or timeout while disputing
- Conflicting attempts to Settle the same Assertion

## Out of Scope

| Topic | Document |
|-------|----------|
| Proof / Statement / Witness / Verifier interface | RFC-0002 |
| Event schemas | RFC-0003 |
| Normative state machine | RFC-0004 |
| Backend interface (Software, Bitcoin, Mock, Future) | RFC-0005 |
| Bitcoin / BitVM3-style backend | RFC-0006 |
| Canonical encoding / multi-language wire format | future RFC |
| Application logic (CubeVM, bridges, …) | out of tree |

## Future Work

- Freeze RFC-0002 through RFC-0005 open questions
- Reference Mock Backend as executable specification of this lifecycle
- Canonical encoding so `beacon-go` / `beacon-ts` / … interoperate
- Bitcoin Backend (RFC-0006) without revising this RFC’s lifecycle

## References

- BitVM3 literature — informative for RFC-0006 only
- `docs/architecture.md` — layers, Cube-driven extraction, repository layout
- `docs/naming.md` — Beacon identity
