//! Settlement outcomes for an assertion.

use crate::id::AssertionId;

/// Terminal truth value of a settled assertion (RFC-0001 / RFC-0004).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Assertion wins — the claim stands.
    Accepted,
    /// Challenger wins — the claim does not stand.
    Rejected,
}

/// Irreversible conclusion of an assertion, including its outcome.
///
/// Backend enforcement side effects (bonds, punishment, chain finality) are
/// Backend-private. This type is the protocol-visible settlement record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Settlement {
    /// Assertion that was settled.
    pub assertion_id: AssertionId,
    /// Exclusive terminal outcome.
    pub outcome: Outcome,
}

impl Settlement {
    /// Build a settlement record.
    #[must_use]
    pub const fn new(assertion_id: AssertionId, outcome: Outcome) -> Self {
        Self {
            assertion_id,
            outcome,
        }
    }

    /// Returns `true` if the assertion won.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self.outcome, Outcome::Accepted)
    }

    /// Returns `true` if the challenger won.
    #[must_use]
    pub const fn is_rejected(self) -> bool {
        matches!(self.outcome, Outcome::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::AssertionId;

    #[test]
    fn settlement_helpers() {
        let id = AssertionId::new();
        let accepted = Settlement::new(id, Outcome::Accepted);
        assert!(accepted.is_accepted());
        assert!(!accepted.is_rejected());

        let rejected = Settlement::new(id, Outcome::Rejected);
        assert!(rejected.is_rejected());
        assert!(!rejected.is_accepted());
    }
}
