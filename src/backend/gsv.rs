//! Garbled SNARK verifier backend (BitVM3 path).
//!
//! # Status
//!
//! This is a **stand-in** that mirrors the integration contract for
//! [`garbled-snark-verifier`](https://github.com/BitVM/garbled-snark-verifier).
//! The real crate is not linked yet (heavy toolchain / edition requirements).
//!
//! # Integration contract (replace the stand-in body)
//!
//! 1. Recover input labels from the Assert opening (Phase A seed → later VSSS/adaptor).
//! 2. Call the library in **Evaluate** mode on the committed garbled verifier.
//! 3. Return the circuit’s `L_valid` / `L_invalid` output label.
//! 4. `commit_l_invalid` must use the `H(L_invalid)` published at GSV setup
//!    (plain `SHA256(L*)` for the current Taproot hashlock leaf).
//!
//! ```toml
//! # Cargo.toml (when ready)
//! garbled-snark-verifier = { git = "https://github.com/BitVM/garbled-snark-verifier", default-features = false }
//! ```

use super::{hashlock_commit, CircuitBackend, EvaluationResult};
use crate::claim_mini::ClaimMini;
use crate::phase_a::opening::DirectSeedOpening;
use sha2::{Digest, Sha256};

/// Stand-in BitVM3 backend. Same claim type as Phase A until real Groth16
/// public inputs are wired; label derivation uses a GSV-specific domain so the
/// path is distinguishable from [`super::ClaimMiniBackend`].
#[derive(Clone, Copy, Debug, Default)]
pub struct GarbledSnarkBackend;

impl GarbledSnarkBackend {
    /// Deterministic stand-in for the garbled verifier’s `L_invalid` label.
    ///
    /// Real GSV: this comes from setup (`output_commit` / decoded false wire).
    pub fn stand_in_l_invalid(claim: &ClaimMini) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"GSV/L_invalid/v1");
        hasher.update(claim.preimage());
        hasher.update(claim.total_in.to_le_bytes());
        hasher.update(claim.total_out.to_le_bytes());
        hasher.update(claim.h_new);
        hasher.finalize().into()
    }

    /// Stand-in for Evaluate mode: validity still uses Claim Mini rules until
    /// a real Groth16 proof + garbled verifier are attached.
    fn stand_in_evaluate(claim: &ClaimMini) -> EvaluationResult {
        if claim.verify() {
            EvaluationResult::Valid
        } else {
            EvaluationResult::Invalid {
                l_invalid: Self::stand_in_l_invalid(claim),
            }
        }
    }
}

impl CircuitBackend for GarbledSnarkBackend {
    type Claim = ClaimMini;

    fn name(&self) -> &'static str {
        "garbled-snark-verifier"
    }

    fn commit_l_invalid(&self, claim: &Self::Claim) -> [u8; 32] {
        // Real GSV: use H(L_invalid) from garbled-circuit setup, not re-derived
        // from the claim. Stand-in keeps assert/evaluate consistent.
        hashlock_commit(&Self::stand_in_l_invalid(claim))
    }

    fn evaluate(&self, claim: &Self::Claim, opening: &DirectSeedOpening) -> EvaluationResult {
        // Real GSV:
        //   let labels = recover_labels(opening);
        //   let verdict = gsv::evaluate(circuit, labels);
        //   match verdict { Valid => ..., Invalid(l) => ... }
        let _labels = opening.derive_label_material();
        Self::stand_in_evaluate(claim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::CircuitBackend;

    #[test]
    fn hashlock_matches_on_invalid() {
        let mut claim = ClaimMini::make_valid(
            [1; 32],
            100,
            40,
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
        );
        claim.total_out = 999;
        let backend = GarbledSnarkBackend;
        let h = backend.commit_l_invalid(&claim);
        let opening = DirectSeedOpening::from_claim_bytes(0, &claim.preimage());
        match backend.evaluate(&claim, &opening) {
            EvaluationResult::Invalid { l_invalid } => {
                assert_eq!(hashlock_commit(&l_invalid), h);
            }
            EvaluationResult::Valid => panic!("expected invalid"),
        }
    }
}
