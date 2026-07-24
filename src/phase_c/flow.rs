//! Phase C dispute flow: adaptor open → (VSSS) reconstruct → garbled Evaluate.

use crate::backend::{hashlock_commit, EvaluationResult};
use crate::claim_mini::ClaimMini;
use crate::phase_a::flow::serialize_claim;
use crate::phase_b::opening::AdaptorOpening;
use crate::phase_c::evaluate::{commit_l_invalid, evaluate_claim};
use crate::phase_c::reconstruct::{reconstruct_label_seed, ShareBundle};
use crate::tx_templates::{
    AssertTemplate, DisproveTemplate, TimeoutTemplate, DEFAULT_DISPUTE_WINDOW,
};
use secp256k1::Keypair;
use sha2::{Digest, Sha256};

/// Engine / challenger flow for Phase C.
#[derive(Clone, Debug, Default)]
pub struct PhaseCFlow {
    /// Optional check-set shares from cut-and-choose setup.
    pub share_bundle: Option<ShareBundle>,
}

impl PhaseCFlow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_share_bundle(bundle: ShareBundle) -> Self {
        Self {
            share_bundle: Some(bundle),
        }
    }

    /// Backend label for logs.
    pub fn name(&self) -> &'static str {
        if cfg!(feature = "gsv-vsss") {
            "phase-c/gsv-vsss"
        } else if cfg!(feature = "gsv") {
            "phase-c/gsv-evaluate"
        } else {
            "phase-c/stand-in"
        }
    }

    /// Engine: adaptor opening + Phase C hashlock commitment.
    pub fn engine_create_assert(
        &self,
        claim: &ClaimMini,
        funding_outpoint: &str,
        signer: &Keypair,
    ) -> Result<(AssertTemplate, AdaptorOpening, [u8; 32]), crate::phase_b::adaptor::AdaptorError>
    {
        let claim_bytes = serialize_claim(claim);
        let opening =
            AdaptorOpening::create(0, &claim_bytes, signer, &mut rand::thread_rng())?;
        let adaptor_share = opening.derive_label_material()?;
        let label_material =
            reconstruct_label_seed(self.share_bundle.as_ref(), &adaptor_share);
        let h_l_invalid = commit_l_invalid(claim, &label_material);

        let assert_tmpl = AssertTemplate {
            funding_outpoint: funding_outpoint.to_string(),
            claim: claim.clone(),
            hash_of_false_label: h_l_invalid,
            dispute_window: DEFAULT_DISPUTE_WINDOW,
        };
        Ok((assert_tmpl, opening, h_l_invalid))
    }

    /// Challenger: extract adaptor secret → reconstruct → Evaluate.
    pub fn challenger_evaluate(
        &self,
        claim: &ClaimMini,
        opening: &AdaptorOpening,
        committed_h_l_invalid: &[u8; 32],
    ) -> EvaluationResult {
        let adaptor_share = match opening.derive_label_material() {
            Ok(s) => s,
            Err(_) => return EvaluationResult::Valid,
        };

        let claim_bytes = serialize_claim(claim);
        let mut hasher = Sha256::new();
        hasher.update(&claim_bytes);
        let expected_hash: [u8; 32] = hasher.finalize().into();
        if opening.public_inputs_hash != expected_hash {
            return EvaluationResult::Valid;
        }

        let label_material =
            reconstruct_label_seed(self.share_bundle.as_ref(), &adaptor_share);
        let result = evaluate_claim(claim, &label_material);
        if let EvaluationResult::Invalid { l_invalid } = &result {
            assert_eq!(
                hashlock_commit(l_invalid),
                *committed_h_l_invalid,
                "Phase C L_invalid does not match hashlock"
            );
        }
        result
    }

    pub fn build_disprove(
        assert_outpoint: &str,
        l_invalid: [u8; 32],
        slash_destination: &str,
    ) -> DisproveTemplate {
        DisproveTemplate {
            assert_outpoint: assert_outpoint.to_string(),
            false_label: l_invalid,
            slash_destination: slash_destination.to_string(),
        }
    }

    pub fn build_timeout(
        assert_outpoint: &str,
        reserve_outpoint: &str,
        engine_pubkey: &str,
    ) -> TimeoutTemplate {
        TimeoutTemplate {
            assert_outpoint: assert_outpoint.to_string(),
            reserve_outpoint: reserve_outpoint.to_string(),
            engine_pubkey: engine_pubkey.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;

    fn sample(valid: bool) -> ClaimMini {
        let mut c = ClaimMini::make_valid(
            [1; 32],
            100_000,
            40_000,
            [10; 32],
            [11; 32],
            [12; 32],
            [13; 32],
        );
        if !valid {
            c.total_out = 999_999;
        }
        c
    }

    #[test]
    fn happy_path() {
        let flow = PhaseCFlow::new();
        let secp = Secp256k1::new();
        let signer = Keypair::new(&secp, &mut rand::thread_rng());
        let claim = sample(true);
        let (_t, opening, h) = flow
            .engine_create_assert(&claim, "txid:0", &signer)
            .unwrap();
        assert!(matches!(
            flow.challenger_evaluate(&claim, &opening, &h),
            EvaluationResult::Valid
        ));
    }

    #[test]
    fn unhappy_path_with_bundle() {
        let secret_placeholder = [0u8; 32];
        let bundle = ShareBundle::synthetic_from_adaptor_secret(&secret_placeholder);
        // Bundle is only mixed into the seed; adaptor opening supplies the real share.
        let flow = PhaseCFlow::with_share_bundle(bundle);
        let secp = Secp256k1::new();
        let signer = Keypair::new(&secp, &mut rand::thread_rng());
        let claim = sample(false);
        let (_t, opening, h) = flow
            .engine_create_assert(&claim, "txid:0", &signer)
            .unwrap();
        match flow.challenger_evaluate(&claim, &opening, &h) {
            EvaluationResult::Invalid { l_invalid } => {
                assert_eq!(hashlock_commit(&l_invalid), h);
            }
            EvaluationResult::Valid => panic!("expected invalid"),
        }
    }
}
