//! Challenge against an assertion.

use crate::id::{AssertionId, ChallengeId, ChallengerId};

/// An active dispute against exactly one [`Assertion`](crate::Assertion).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Challenge {
    /// Unique challenge id.
    pub id: ChallengeId,
    /// Assertion under dispute.
    pub assertion_id: AssertionId,
    /// Party that opened the challenge.
    pub challenger: ChallengerId,
}

impl Challenge {
    /// Create a new challenge referencing `assertion_id`.
    #[must_use]
    pub fn new(assertion_id: AssertionId, challenger: ChallengerId) -> Self {
        Self {
            id: ChallengeId::new(),
            assertion_id,
            challenger,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::AssertionId;

    #[test]
    fn challenge_binds_one_assertion() {
        let assertion = AssertionId::new();
        let challenge = Challenge::new(assertion, ChallengerId::new("alice"));
        assert_eq!(challenge.assertion_id, assertion);
        assert_eq!(challenge.challenger.as_str(), "alice");
    }
}
