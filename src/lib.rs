//! Beacon – BitVM3-style dispute layer for Cube
//!
//! Phase A: direct seed opening + real Bitcoin transaction builders.
//! Circuit evaluation is pluggable via [`backend::CircuitBackend`]:
//! - [`backend::ClaimMiniBackend`] — works today
//! - [`backend::GarbledSnarkBackend`] — stand-in for
//!   [garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier)

pub mod backend;
pub mod claim_mini;
pub mod phase_a;
pub mod tx_templates;

pub use backend::{
    hashlock_commit, CircuitBackend, ClaimMiniBackend, EvaluationResult, GarbledSnarkBackend,
};
pub use claim_mini::{ClaimMini, OutputWire};
pub use phase_a::flow::{serialize_claim, PhaseAFlow};
pub use phase_a::opening::DirectSeedOpening;
pub use phase_a::regtest_run::{connect_regtest, run_phase_a_regtest, RegtestOutcome};
pub use phase_a::regtest_tx::{
    build_assert_tx, build_disprove_tx, build_timeout_tx, p2tr_address, sign_assert_keypath,
    AssertBuildResult, REGTEST_DISPUTE_WINDOW,
};
