//! Beacon core — reference implementation of the assertion protocol.
//!
//! This crate contains **protocol** types (and a thin [`Verifiable`] boundary).
//! No Bitcoin, networking, database, or named proof-system code.
//!
//! Normative specs: `rfcs/0001-assertion-protocol.md`, `rfcs/0004-state-machine.md`.

#![forbid(unsafe_code)]

mod assertion;
mod backend;
mod challenge;
mod error;
mod id;
mod proof;
mod settlement;
mod state;
mod time;

pub use assertion::Assertion;
pub use backend::BackendId;
pub use challenge::Challenge;
pub use error::{Error, Result};
pub use id::{AssertionId, ChallengeId, ChallengerId};
pub use proof::Verifiable;
pub use settlement::{Outcome, Settlement};
pub use state::AssertionState;
pub use time::{Deadline, Instant};
