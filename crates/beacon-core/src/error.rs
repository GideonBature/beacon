//! Protocol and dispute errors.

use core::fmt;

use crate::state::AssertionState;

/// Errors produced by Beacon core protocol operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Referenced assertion does not exist.
    NotFound,
    /// Operation is illegal for the assertion's current state.
    InvalidState {
        /// Status observed when the operation was attempted.
        current: AssertionState,
    },
    /// Challenge attempted after the challenge window closed.
    ChallengeWindowClosed,
    /// Assertion was already settled.
    AlreadySettled,
    /// Finalize called while dispute resolution is still pending.
    DisputePending,
    /// Assertion or evidence failed validation at the protocol edge.
    MalformedAssertion,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "assertion not found"),
            Self::InvalidState { current } => {
                write!(f, "invalid state transition from {current:?}")
            }
            Self::ChallengeWindowClosed => write!(f, "challenge window closed"),
            Self::AlreadySettled => write!(f, "assertion already settled"),
            Self::DisputePending => write!(f, "dispute still pending"),
            Self::MalformedAssertion => write!(f, "malformed assertion"),
        }
    }
}

impl std::error::Error for Error {}

/// Result alias for Beacon core operations.
pub type Result<T> = core::result::Result<T, Error>;
