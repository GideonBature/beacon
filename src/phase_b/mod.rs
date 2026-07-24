//! Phase B – Schnorr adaptor extractable opening.
//!
//! Replaces the Phase A direct seed with an adaptor-signature offset.
//! Taproot connector / Disprove / Timeout stay unchanged.

pub mod adaptor;
pub mod flow;
pub mod opening;

pub use adaptor::{complete_and_extract, create_adapted_signature, extract_adaptor_secret};
pub use flow::PhaseBFlow;
pub use opening::AdaptorOpening;
