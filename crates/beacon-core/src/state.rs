//! Normative assertion lifecycle statuses (RFC-0004).

/// Lifecycle status of an [`Assertion`](crate::Assertion).
///
/// Per RFC-0004:
/// - Local drafting is **not** a protocol status.
/// - `Settled` is finalization of a terminal outcome, not a fifth status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AssertionState {
    /// Posted; challenge window open; no challenge yet.
    Asserted,
    /// A challenge is open; backend dispute procedure running.
    Disputing,
    /// Terminal: the claim stands (assertion wins).
    Accepted,
    /// Terminal: the claim does not stand (challenger wins).
    Rejected,
}

impl AssertionState {
    /// Returns `true` if this status is a terminal truth value.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Accepted | Self::Rejected)
    }

    /// Returns `true` if a challenge may be opened (RFC-0004 T3).
    #[must_use]
    pub const fn can_challenge(self) -> bool {
        matches!(self, Self::Asserted)
    }

    /// Returns `true` if the assertion is still in its challenge window phase.
    #[must_use]
    pub const fn in_challenge_window(self) -> bool {
        matches!(self, Self::Asserted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_states() {
        assert!(!AssertionState::Asserted.is_terminal());
        assert!(!AssertionState::Disputing.is_terminal());
        assert!(AssertionState::Accepted.is_terminal());
        assert!(AssertionState::Rejected.is_terminal());
    }

    #[test]
    fn only_asserted_can_be_challenged() {
        assert!(AssertionState::Asserted.can_challenge());
        assert!(!AssertionState::Disputing.can_challenge());
        assert!(!AssertionState::Accepted.can_challenge());
        assert!(!AssertionState::Rejected.can_challenge());
    }
}
