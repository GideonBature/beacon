//! End-to-end Phase B flow (adaptor opening + same Disprove / Timeout graph).

use crate::backend::{hashlock_commit, CircuitBackend, ClaimMiniBackend, EvaluationResult};
use crate::claim_mini::ClaimMini;
use crate::opening::LabelOpening;
use crate::phase_a::flow::serialize_claim;
use crate::phase_b::opening::AdaptorOpening;
use crate::tx_templates::{
    AssertTemplate, DisproveTemplate, TimeoutTemplate, DEFAULT_DISPUTE_WINDOW,
};
use secp256k1::Keypair;
use sha2::{Digest, Sha256};

/// Dispute flow with Phase B adaptor openings.
pub struct PhaseBFlow<B: CircuitBackend = ClaimMiniBackend> {
    backend: B,
}

impl Default for PhaseBFlow<ClaimMiniBackend> {
    fn default() -> Self {
        Self::new(ClaimMiniBackend)
    }
}

impl<B: CircuitBackend<Claim = ClaimMini>> PhaseBFlow<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Engine: adaptor opening + hashlock commitment.
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
        let h_l_invalid = self.backend.commit_l_invalid(claim);

        let assert_tmpl = AssertTemplate {
            funding_outpoint: funding_outpoint.to_string(),
            claim: claim.clone(),
            hash_of_false_label: h_l_invalid,
            dispute_window: DEFAULT_DISPUTE_WINDOW,
        };

        Ok((assert_tmpl, opening, h_l_invalid))
    }

    /// Challenger: extract adaptor secret, then evaluate via backend.
    pub fn challenger_evaluate(
        &self,
        claim: &ClaimMini,
        opening: &AdaptorOpening,
        committed_h_l_invalid: &[u8; 32],
    ) -> EvaluationResult {
        // Must extract cleanly (signature + adaptor point checks).
        let _labels = match opening.derive_label_material() {
            Ok(l) => l,
            Err(_) => {
                // Treat broken opening as non-evaluable; stand-in: Valid so Engine
                // cannot be spuriously slashed. Real systems abort the challenge.
                return EvaluationResult::Valid;
            }
        };

        let claim_bytes = serialize_claim(claim);
        let mut hasher = Sha256::new();
        hasher.update(&claim_bytes);
        let expected_hash: [u8; 32] = hasher.finalize().into();
        if opening.public_inputs_hash() != expected_hash {
            return EvaluationResult::Valid;
        }

        let result = self.backend.evaluate(claim, opening);
        if let EvaluationResult::Invalid { l_invalid } = &result {
            assert_eq!(
                hashlock_commit(l_invalid),
                *committed_h_l_invalid,
                "L_invalid does not match hashlock commitment ({})",
                self.backend.name()
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

    fn sample_claim() -> ClaimMini {
        ClaimMini::make_valid(
            [1; 32],
            100_000,
            40_000,
            [10; 32],
            [11; 32],
            [12; 32],
            [13; 32],
        )
    }

    #[test]
    fn happy_path_adaptor() {
        let flow = PhaseBFlow::new(ClaimMiniBackend);
        let secp = Secp256k1::new();
        let signer = Keypair::new(&secp, &mut rand::thread_rng());
        let claim = sample_claim();
        let (_tmpl, opening, h) = flow
            .engine_create_assert(&claim, "txid:0", &signer)
            .unwrap();
        assert!(matches!(
            flow.challenger_evaluate(&claim, &opening, &h),
            EvaluationResult::Valid
        ));
    }

    #[test]
    fn unhappy_path_adaptor() {
        let flow = PhaseBFlow::new(ClaimMiniBackend);
        let secp = Secp256k1::new();
        let signer = Keypair::new(&secp, &mut rand::thread_rng());
        let mut claim = sample_claim();
        claim.total_out = 250_000;
        let (_tmpl, opening, h) = flow
            .engine_create_assert(&claim, "txid:0", &signer)
            .unwrap();
        match flow.challenger_evaluate(&claim, &opening, &h) {
            EvaluationResult::Invalid { l_invalid } => {
                assert_eq!(hashlock_commit(&l_invalid), h);
            }
            EvaluationResult::Valid => panic!("should be invalid"),
        }
    }
}
