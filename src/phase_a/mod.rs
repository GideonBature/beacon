//! Phase A – Minimal end-to-end prototype
//!
//! Direct seed opening + signed Taproot builders + optional regtest runner.
//! Phase B (`--adaptor`) swaps in [`crate::phase_b::AdaptorOpening`] on the
//! same builders via [`crate::phase_a::regtest_tx::OpeningMode`].

pub mod flow;
pub mod opening;
pub mod regtest_run;
pub mod regtest_tx;
