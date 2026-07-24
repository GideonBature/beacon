//! Beacon – BitVM3-style dispute layer for Cube
//!
//! Phase A: direct seed opening + real Bitcoin transaction builders.
//! Phase B: Schnorr adaptor extractable opening (same Taproot graph).
//! Phase C: VSSS reconstruct + garbled Evaluate (tiny circuit MVP).
//! Circuit evaluation is pluggable via [`backend::CircuitBackend`]:
//! - [`backend::ClaimMiniBackend`] — works today
//! - [`backend::GarbledSnarkBackend`] — stand-in for
//!   [garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier)

pub mod backend;
pub mod claim_mini;
pub mod phase_a;
pub mod phase_b;
pub mod phase_c;
pub mod opening;
pub mod tx_templates;
pub mod witness;

pub use backend::{
    hashlock_commit, CircuitBackend, ClaimMiniBackend, EvaluationResult, GarbledSnarkBackend,
};
pub use claim_mini::{ClaimMini, OutputWire};
pub use opening::{AssertOpening, LabelOpening};
pub use phase_a::flow::{deserialize_claim, serialize_claim, PhaseAFlow};
pub use phase_a::opening::DirectSeedOpening;
pub use phase_a::regtest_run::{
    connect_regtest, run_phase_a_regtest, run_phase_b_regtest, run_phase_c_regtest, RegtestOutcome,
};
pub use phase_a::regtest_tx::{
    build_assert_tx, build_assert_tx_with_assert_opening, build_assert_tx_with_opening,
    build_disprove_tx, build_timeout_tx, p2tr_address, sign_assert_keypath, AssertBuildResult,
    OpeningMode, REGTEST_DISPUTE_WINDOW,
};
pub use phase_b::flow::PhaseBFlow;
pub use phase_b::opening::AdaptorOpening;
pub use phase_c::ciphertext_store::{CiphertextMeta, CiphertextStore, StoreError};
pub use phase_c::flow::PhaseCFlow;
pub use phase_c::reconstruct::{reconstruct_label_seed, ShareBundle};
pub use phase_c::schedule::{
    check_openings_from_store, commits_from_store, fixed_schedule, open_check_instances,
    require_eval_committed, sample_schedule, CheckOpening, CutAndChooseParams,
    CutAndChooseSchedule, InstanceCommit, ScheduleError,
};

pub use witness::{
    attach_op_return_output, attach_to_funding_witness, extract_from_funding_witness,
    extract_from_op_return, AssertWitnessV1, PublicStatement, FORMAT_V1, MAGIC,
};

#[cfg(feature = "gsv")]
pub use phase_c::{
    evaluate_and_from_store, evaluate_bundle_from_store, evaluate_from_store, garble_and_to_store,
    load_and_package, load_sidecar, setup_garble_to_store, verify_check_regarble, AndEvalPackage,
    Groth16AssertBundle, Groth16EvalSidecar, PhaseCPlusAssert, PhaseCPlusFlow, DEFAULT_K,
    GROTH16_CAPACITY,
};

#[cfg(feature = "gsv-vsss")]
pub use phase_b::gsv_adaptor::{GsvAdaptorOpening, VERSION_GSV_ADAPTOR};
#[cfg(feature = "gsv-vsss")]
pub use phase_c::adaptor_share_from_gsv_fr_be;
