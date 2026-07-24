//! Beacon – BitVM3-style dispute layer for Cube
//!
//! Phase A: direct seed opening + real Bitcoin transaction builders.
//! Phase B: Schnorr adaptor extractable opening (same Taproot graph).
//! Circuit evaluation is pluggable via [`backend::CircuitBackend`]:
//! - [`backend::ClaimMiniBackend`] — works today
//! - [`backend::GarbledSnarkBackend`] — stand-in for
//!   [garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier)

pub mod backend;
pub mod claim_mini;
pub mod phase_a;
pub mod phase_b;
pub mod opening;
pub mod tx_templates;

pub use backend::{
    hashlock_commit, CircuitBackend, ClaimMiniBackend, EvaluationResult, GarbledSnarkBackend,
};
pub use claim_mini::{ClaimMini, OutputWire};
pub use opening::{AssertOpening, LabelOpening};
pub use phase_a::flow::{serialize_claim, PhaseAFlow};
pub use phase_a::opening::DirectSeedOpening;
pub use phase_a::regtest_run::{
    connect_regtest, run_phase_a_regtest, run_phase_b_regtest, RegtestOutcome,
};
pub use phase_a::regtest_tx::{
    build_assert_tx, build_assert_tx_with_opening, build_disprove_tx, build_timeout_tx,
    p2tr_address, sign_assert_keypath, AssertBuildResult, OpeningMode, REGTEST_DISPUTE_WINDOW,
};
pub use phase_b::flow::PhaseBFlow;
pub use phase_b::opening::AdaptorOpening;
