//! Phase C – VSSS reconstruct + garbled Evaluate.
//!
//! - **Phase C MVP**: tiny AND Garble → Evaluate (`evaluate`, `flow`)
//! - **Ciphertext store**: off-chain CT persistence + hash verify (`ciphertext_store`)
//! - **Phase C+**: real `garbled_groth16::verify` (`groth16`, `plus`) — prefer `--release`

pub mod ciphertext_store;
pub mod evaluate;
pub mod flow;
pub mod labels;
pub mod reconstruct;
pub mod schedule;

#[cfg(feature = "gsv")]
pub mod groth16;
#[cfg(feature = "gsv")]
pub mod persist;
#[cfg(feature = "gsv")]
pub mod plus;
#[cfg(feature = "gsv")]
pub mod sidecar;

pub use ciphertext_store::{CiphertextMeta, CiphertextStore, StoreError};
pub use evaluate::{commit_l_invalid, evaluate_claim};
pub use flow::PhaseCFlow;
pub use labels::{expand_label_bytes, seed_from_label_material};
pub use reconstruct::{reconstruct_label_seed, ShareBundle};

#[cfg(feature = "gsv-vsss")]
pub use reconstruct::adaptor_share_from_gsv_fr_be;
pub use schedule::{
    check_openings_from_store, commits_from_store, fixed_schedule, open_check_instances,
    require_eval_committed, sample_schedule, validate_schedule, CheckOpening, CutAndChooseParams,
    CutAndChooseSchedule, InstanceCommit, ScheduleError,
};

#[cfg(feature = "gsv")]
pub use groth16::{
    evaluate_bundle_from_store, evaluate_from_store, setup_garble_to_store, Groth16AssertBundle,
    DEFAULT_K, GROTH16_CAPACITY,
};
#[cfg(feature = "gsv")]
pub use persist::{
    evaluate_and_from_store, garble_and_to_store, load_and_package, verify_check_regarble,
    AndEvalPackage,
};
#[cfg(feature = "gsv")]
pub use plus::{PhaseCPlusAssert, PhaseCPlusFlow};
#[cfg(feature = "gsv")]
pub use sidecar::{load_sidecar, write_sidecar, Groth16EvalSidecar};
