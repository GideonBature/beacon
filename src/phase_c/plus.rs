//! Phase C+ dispute flow: adaptor open → garbled Groth16 Evaluate → Disprove|Timeout.

use crate::backend::{hashlock_commit, EvaluationResult};
use crate::claim_mini::ClaimMini;
use crate::phase_a::flow::serialize_claim;
use crate::phase_b::opening::AdaptorOpening;
use crate::phase_c::groth16::{
    commit_from_bundle, evaluate_bundle, setup_garble, Groth16AssertBundle, DEFAULT_K,
};
use crate::phase_c::reconstruct::{reconstruct_label_seed, ShareBundle};
use crate::tx_templates::{
    AssertTemplate, DisproveTemplate, TimeoutTemplate, DEFAULT_DISPUTE_WINDOW,
};
use secp256k1::Keypair;
use sha2::{Digest, Sha256};

/// Engine Assert package for Phase C+.
pub struct PhaseCPlusAssert {
    pub template: AssertTemplate,
    pub opening: AdaptorOpening,
    pub h_l_invalid: [u8; 32],
    pub groth16: Groth16AssertBundle,
}

/// Phase C+ flow (requires `gsv`).
#[derive(Clone, Debug, Default)]
pub struct PhaseCPlusFlow {
    pub share_bundle: Option<ShareBundle>,
    pub k: u32,
}

impl PhaseCPlusFlow {
    pub fn new() -> Self {
        Self {
            share_bundle: None,
            k: DEFAULT_K,
        }
    }

    pub fn with_share_bundle(bundle: ShareBundle) -> Self {
        Self {
            share_bundle: Some(bundle),
            k: DEFAULT_K,
        }
    }

    pub fn with_k(mut self, k: u32) -> Self {
        self.k = k;
        self
    }

    pub fn name(&self) -> &'static str {
        "phase-c+/garbled-groth16"
    }

    /// Engine: adaptor opening + garble Groth16 verifier + hashlock commit.
    ///
    /// Uses a valid proof when `claim.verify()`; otherwise posts a broken proof
    /// so Evaluate yields `L_invalid` (Disprove).
    pub fn engine_create_assert(
        &self,
        claim: &ClaimMini,
        funding_outpoint: &str,
        signer: &Keypair,
    ) -> Result<PhaseCPlusAssert, String> {
        let claim_bytes = serialize_claim(claim);
        let opening = AdaptorOpening::create(0, &claim_bytes, signer, &mut rand::thread_rng())
            .map_err(|e| e.to_string())?;
        let adaptor_share = opening.derive_label_material().map_err(|e| e.to_string())?;
        let label_material =
            reconstruct_label_seed(self.share_bundle.as_ref(), &adaptor_share);

        let break_proof = !claim.verify();
        let groth16 = setup_garble(&label_material, break_proof, self.k)?;
        let h_l_invalid = commit_from_bundle(&groth16);

        let template = AssertTemplate {
            funding_outpoint: funding_outpoint.to_string(),
            claim: claim.clone(),
            hash_of_false_label: h_l_invalid,
            dispute_window: DEFAULT_DISPUTE_WINDOW,
        };

        Ok(PhaseCPlusAssert {
            template,
            opening,
            h_l_invalid,
            groth16,
        })
    }

    /// Challenger: verify adaptor opening binds the claim, then Evaluate Groth16.
    pub fn challenger_evaluate(
        &self,
        claim: &ClaimMini,
        opening: &AdaptorOpening,
        bundle: &Groth16AssertBundle,
        committed_h_l_invalid: &[u8; 32],
    ) -> Result<EvaluationResult, String> {
        let _adaptor_share = opening.derive_label_material().map_err(|e| e.to_string())?;

        let claim_bytes = serialize_claim(claim);
        let mut hasher = Sha256::new();
        hasher.update(&claim_bytes);
        let expected_hash: [u8; 32] = hasher.finalize().into();
        if opening.public_inputs_hash != expected_hash {
            return Err("adaptor opening does not bind claim".into());
        }

        if commit_from_bundle(bundle) != *committed_h_l_invalid {
            return Err("bundle L_invalid does not match Assert hashlock".into());
        }

        let result = evaluate_bundle(bundle)?;
        if let EvaluationResult::Invalid { l_invalid } = &result {
            assert_eq!(
                hashlock_commit(l_invalid),
                *committed_h_l_invalid,
                "Phase C+ L_invalid hashlock mismatch"
            );
        }
        Ok(result)
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
