# RFC-0002: Proof Interface

- **Status:** Draft
- **Authors:** TBD
- **Created:** 2026-07-23
- **Depends on:** RFC-0001
- **See also:** [docs/traits.md](../docs/traits.md)

## Abstract

Evidence enters Beacon through a **Verifiable** boundary. Named proof systems
(Groth16, STARKs, …) are adapters behind that boundary. Backends MUST NOT
depend on those names.

## Motivation

If `DisputeBackend` is generic over Groth16 types, the engine is not
backend-agnostic—it is Groth16-centric with extra steps. BitVM-family papers
often garble a specific verifier; that is valid *inside* a Backend, not as the
protocol’s public surface.

## Verifiable

Capability required of assertion evidence:

```text
Verifiable
  statement() -> Statement
  check() -> bool          // software/mock path
```

Requirements:

1. `check` MUST be deterministic for fixed evidence.
2. Bitcoin / interactive dispute backends MAY refrain from calling `check` and
   instead run a dispute protocol that is sound w.r.t. the same relation.
3. Generic Backend interfaces refer only to `Verifiable` (or associated
   `Evidence: Verifiable`), never to Groth16/SP1/… types.

## ProofSystem (adapter)

Optional producer API for applications that generate evidence inside the
Beacon workspace:

```text
ProofSystem
  associated: Statement, Witness, Proof: Verifiable
  prove(statement, witness) -> Proof
```

Applications MAY construct `Verifiable` evidence without using a Beacon
`ProofSystem` trait object.

## Commitment

Per RFC-0001, an Assertion may store a Commitment while the full evidence blob
lives elsewhere. Commitment construction SHOULD be binding to the Verifiable
evidence. Exact hash function is Backend- or encoding-RFC defined.

## Relationship to Assertion Engine

```text
Application / ProofSystem
        │
        ▼
   Verifiable evidence
        │
        ▼
 DisputeBackend.assert / challenge / finalize
        │
        ▼
 Assertion lifecycle (RFC-0004)
```

## Out of scope

Garbling, labels, hashlocks (RFC-0006). Event schemas (RFC-0003). Concrete
Cube circuits.

## Open questions

1. Is `check()` required on the trait for Bitcoin backends, or should Verifiable
   split into `Verifiable` + `SoftwareCheckable`?
2. Who owns Commitment derivation—evidence type or Backend?
