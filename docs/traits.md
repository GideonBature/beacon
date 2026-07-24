# Trait Hierarchy (Design Sketch)

- **Status:** Draft (Phase 0 — not yet implemented)
- **Normative companions:** [RFC-0001](../rfcs/0001-assertion-protocol.md),
  [RFC-0002](../rfcs/0002-proof-interface.md),
  [RFC-0005](../rfcs/0005-backends.md)

## Naming

Prefer **AssertionEngine** as the façade. Avoid `ProofEngine` as the primary
type—the runtime is assertion-centric.

```text
AssertionEngine
    │
    ├── uses ProofSystem (optional; apps may bring their own evidence)
    └── delegates lifecycle to DisputeBackend
```

## Layering

```text
ProofSystem     — produce concrete evidence (Groth16, STARK, …)
Verifiable      — what backends see (proof-system opaque)
DisputeBackend  — assert / challenge / finalize
AssertionEngine — application-facing orchestration + events
```

**Biggest rule:** backends MUST NOT know Groth16, SP1, Halo2, Plonky, or
RISC Zero. They only see `Verifiable`.

## `Verifiable`

```rust
/// Evidence a backend can check without knowing which proof system produced it.
pub trait Verifiable {
    type Statement;

    fn statement(&self) -> &Self::Statement;

    /// Backend-local check. Mock/software call this directly.
    /// Bitcoin backends may ignore this and use dispute protocols instead,
    /// but the evidence still enters through this abstraction.
    fn check(&self) -> bool;
}
```

Concrete proofs implement `Verifiable`. Adapters live in optional crates
(`beacon-groth16`, …), never in `DisputeBackend` generics as named crypto types.

## `ProofSystem`

```rust
pub trait ProofSystem {
    type Statement;
    type Witness;
    type Proof: Verifiable<Statement = Self::Statement>;

    fn prove(
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, ProofError>;
}
```

`verify` is `proof.check()` (or a free function delegating to it). Keeping
`verify` on `ProofSystem` is optional sugar.

## `DisputeBackend`

```rust
pub trait DisputeBackend {
    type Statement;
    type Evidence: Verifiable<Statement = Self::Statement>;
    type AssertionId;
    type ChallengerId;

    fn assert(
        &mut self,
        evidence: Self::Evidence,
        timeout: Timeout,
    ) -> Result<Self::AssertionId, DisputeError>;

    fn challenge(
        &mut self,
        assertion: Self::AssertionId,
        challenger: Self::ChallengerId,
    ) -> Result<(), DisputeError>;

    fn finalize(
        &mut self,
        assertion: Self::AssertionId,
    ) -> Result<Settlement, DisputeError>;
}
```

No Bitcoin. No Cube. No proof-system names.

Note: parameterized by associated `Evidence: Verifiable` rather than
`DisputeBackend<P: ProofSystem>`, so a backend never names `P`.

## `AssertionEngine`

```rust
pub struct AssertionEngine<B: DisputeBackend> {
    backend: B,
    // event subscribers, clock, …
}

impl<B: DisputeBackend> AssertionEngine<B> {
    pub fn assert(&mut self, evidence: B::Evidence, timeout: Timeout)
        -> Result<B::AssertionId, DisputeError>;

    pub fn challenge(
        &mut self,
        assertion: B::AssertionId,
        challenger: B::ChallengerId,
    ) -> Result<(), DisputeError>;

    pub fn finalize(
        &mut self,
        assertion: B::AssertionId,
    ) -> Result<Settlement, DisputeError>;
}
```

## Settlement

```rust
pub enum Outcome {
    /// Assertion wins
    Accepted,
    /// Challenger wins
    Rejected,
}

pub struct Settlement {
    pub assertion_id: /* … */,
    pub outcome: Outcome,
}
```

## Intentionally absent from core traits

| Absent | Why |
|--------|-----|
| `garble` / labels | Backend detail (RFC-0006) |
| Bitcoin tx types | `beacon-bitcoin` |
| CubeVM / state roots | Application |
| Named SNARK types on Backend | Violates Invariant 6 |

## Evolution

```text
Evidence:   trivial Verifiable → Groth16 wrapper → other systems
Backend:    Mock → Bitcoin/BitVM3-style → covenants / future
Engine API: unchanged
```
