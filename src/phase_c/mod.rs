//! Phase C – VSSS reconstruct + garbled Evaluate.
//!
//! - **Phase C MVP**: tiny AND Garble → Evaluate (`evaluate`, `flow`)
//! - **Phase C+**: real `garbled_groth16::verify` (`groth16`, `plus`) — prefer `--release`

pub mod evaluate;
pub mod flow;
pub mod labels;
pub mod reconstruct;

#[cfg(feature = "gsv")]
pub mod groth16;
#[cfg(feature = "gsv")]
pub mod plus;

pub use evaluate::{commit_l_invalid, evaluate_claim};
pub use flow::PhaseCFlow;
pub use labels::{expand_label_bytes, seed_from_label_material};
pub use reconstruct::{reconstruct_label_seed, ShareBundle};

#[cfg(feature = "gsv")]
pub use groth16::{Groth16AssertBundle, DEFAULT_K, GROTH16_CAPACITY};
#[cfg(feature = "gsv")]
pub use plus::{PhaseCPlusAssert, PhaseCPlusFlow};
