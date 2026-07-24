//! Strong identifiers for Beacon protocol objects.

use core::fmt;
use uuid::Uuid;

/// Unique identifier for an [`Assertion`](crate::Assertion).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AssertionId(Uuid);

impl AssertionId {
    /// Generate a new random assertion id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wrap an existing UUID.
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Borrow the inner UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for AssertionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AssertionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Unique identifier for a [`Challenge`](crate::Challenge).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChallengeId(Uuid);

impl ChallengeId {
    /// Generate a new random challenge id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wrap an existing UUID.
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Borrow the inner UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for ChallengeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ChallengeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Identifier for a dispute backend implementation.
///
/// Opaque to the protocol: `"mock"`, `"bitcoin"`, etc. are Backend concerns.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BackendId(String);

impl BackendId {
    /// Create a backend id from any string-like value.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the raw id string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BackendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Identifier for a challenger (party opening a dispute).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChallengerId(String);

impl ChallengerId {
    /// Create a challenger id from any string-like value.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the raw id string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ChallengerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_ids_are_unique() {
        assert_ne!(AssertionId::new(), AssertionId::new());
    }

    #[test]
    fn challenge_ids_are_unique() {
        assert_ne!(ChallengeId::new(), ChallengeId::new());
    }
}
