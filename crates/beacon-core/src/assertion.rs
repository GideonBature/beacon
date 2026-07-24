//! The central Beacon protocol object: an assertion.

use crate::id::{AssertionId, BackendId};
use crate::state::AssertionState;
use crate::time::Deadline;

/// A public claim that a [`statement`](Assertion::statement) is true.
///
/// This is the central object of Beacon (RFC-0001). Challenges and settlements
/// reference an assertion by [`AssertionId`].
///
/// Type parameters:
/// - `S` — statement (application-defined)
/// - `P` — proof / evidence (application- or adapter-defined)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion<S, P> {
    /// Unique assertion id.
    pub id: AssertionId,
    /// Public claim being asserted.
    pub statement: S,
    /// Evidence associated with the claim (full proof or commitment handle).
    pub proof: P,
    /// Backend that owns verification / enforcement for this assertion.
    pub backend: BackendId,
    /// Challenge-window deadline.
    pub deadline: Deadline,
    /// Current lifecycle status.
    pub state: AssertionState,
    /// Whether backend finalization side effects for a terminal state completed.
    ///
    /// Per RFC-0004 this is a derived predicate flag, not a fifth status.
    pub settled: bool,
}

impl<S, P> Assertion<S, P> {
    /// Create a newly posted assertion in [`AssertionState::Asserted`].
    #[must_use]
    pub fn new(statement: S, proof: P, backend: BackendId, deadline: Deadline) -> Self {
        Self {
            id: AssertionId::new(),
            statement,
            proof,
            backend,
            deadline,
            state: AssertionState::Asserted,
            settled: false,
        }
    }

    /// Returns `true` if the assertion has a terminal status **and** has been
    /// finalized (`settled`).
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        self.settled && self.state.is_terminal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Deadline;

    #[test]
    fn new_assertion_starts_asserted_and_unsettle() {
        let a = Assertion::new(
            "stmt",
            true,
            BackendId::new("mock"),
            Deadline::from_raw(100),
        );
        assert_eq!(a.state, AssertionState::Asserted);
        assert!(!a.settled);
        assert!(!a.is_settled());
        assert_eq!(a.statement, "stmt");
        assert!(a.proof);
    }
}
