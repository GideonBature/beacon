//! Phase C – VSSS reconstruct + garbled Evaluate (tiny circuit MVP).
//!
//! Full garbled Groth16 (~billions of gates) stays an upstream release-only
//! workload. This module wires the BitVM3 *shape*:
//!
//! 1. Phase B adaptor opening → label / share material  
//! 2. Optional VSSS reconstruction (`gsv-vsss`)  
//! 3. Real `streaming_garbling` → `streaming_evaluation` on a toy AND circuit  
//! 4. Same Taproot Disprove hashlock on `L*` = expand(output label0)

pub mod evaluate;
pub mod flow;
pub mod labels;
pub mod reconstruct;

pub use evaluate::{commit_l_invalid, evaluate_claim};
pub use flow::PhaseCFlow;
pub use labels::{expand_label_bytes, seed_from_label_material};
pub use reconstruct::{reconstruct_label_seed, ShareBundle};
