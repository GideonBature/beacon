//! Proof / evidence boundary.
//!
//! Named proof systems (Groth16, SP1, …) must not appear in Backend APIs.
//! Concrete evidence types will implement [`Verifiable`] in a later commit.
//! This module exists so the crate layout matches the intended protocol surface.

/// Evidence a backend can check without knowing which proof system produced it.
///
/// Bitcoin backends may use dispute protocols instead of calling [`check`](Self::check),
/// but evidence still enters the engine through this abstraction (RFC-0002).
pub trait Verifiable {
    /// Public statement this evidence supports.
    type Statement;

    /// Borrow the statement.
    fn statement(&self) -> &Self::Statement;

    /// Software/mock validity check. Deterministic for fixed evidence.
    fn check(&self) -> bool;
}
