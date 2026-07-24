//! Dispute backend contract and assertion engine façade.

use crate::error::Result;
use crate::id::{AssertionId, ChallengerId};
use crate::proof::Verifiable;
use crate::settlement::Settlement;
use crate::time::Deadline;

/// Backend that realizes the Beacon assertion lifecycle (RFC-0005).
///
/// Backends consume [`Verifiable`] evidence only. They must not name specific
/// proof systems in this interface.
pub trait DisputeBackend {
    /// Evidence type accepted by this backend.
    type Evidence: Verifiable;

    /// Post an assertion. Optimistic: evidence is not required to pass
    /// [`Verifiable::check`] at assert time.
    ///
    /// Transitions to [`AssertionState::Asserted`](crate::AssertionState::Asserted).
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedAssertion`](crate::Error::MalformedAssertion) if
    /// the backend rejects the evidence envelope (rare for mock).
    fn assert(&mut self, evidence: Self::Evidence, deadline: Deadline) -> Result<AssertionId>;

    /// Open a challenge against an assertion still in its challenge window.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`](crate::Error::NotFound)
    /// - [`Error::InvalidState`](crate::Error::InvalidState)
    /// - [`Error::ChallengeWindowClosed`](crate::Error::ChallengeWindowClosed)
    /// - [`Error::AlreadySettled`](crate::Error::AlreadySettled)
    fn challenge(&mut self, assertion: AssertionId, challenger: ChallengerId) -> Result<()>;

    /// Drive the assertion to a terminal settlement when the state machine allows.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`](crate::Error::NotFound)
    /// - [`Error::AlreadySettled`](crate::Error::AlreadySettled)
    /// - [`Error::DisputePending`](crate::Error::DisputePending)
    /// - [`Error::InvalidState`](crate::Error::InvalidState)
    fn finalize(&mut self, assertion: AssertionId) -> Result<Settlement>;
}

/// Application-facing orchestration over a [`DisputeBackend`].
///
/// Applications depend on this API, not on backend-specific behavior.
#[derive(Debug, Default)]
pub struct Engine<B> {
    backend: B,
}

impl<B> Engine<B> {
    /// Create an engine around a backend.
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Borrow the backend.
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Borrow the backend mutably (e.g. to advance a mock clock).
    pub const fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Consume the engine and return the backend.
    #[must_use]
    pub fn into_backend(self) -> B {
        self.backend
    }
}

impl<B: DisputeBackend> Engine<B> {
    /// Post an assertion via the backend.
    ///
    /// # Errors
    ///
    /// Propagates backend errors from [`DisputeBackend::assert`].
    pub fn assert(&mut self, evidence: B::Evidence, deadline: Deadline) -> Result<AssertionId> {
        self.backend.assert(evidence, deadline)
    }

    /// Open a challenge via the backend.
    ///
    /// # Errors
    ///
    /// Propagates backend errors from [`DisputeBackend::challenge`].
    pub fn challenge(&mut self, assertion: AssertionId, challenger: ChallengerId) -> Result<()> {
        self.backend.challenge(assertion, challenger)
    }

    /// Finalize / settle via the backend.
    ///
    /// # Errors
    ///
    /// Propagates backend errors from [`DisputeBackend::finalize`].
    pub fn finalize(&mut self, assertion: AssertionId) -> Result<Settlement> {
        self.backend.finalize(assertion)
    }
}
