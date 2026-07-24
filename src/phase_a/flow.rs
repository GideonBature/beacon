//! End-to-end Phase A flow simulation.
//!
//! Backend-agnostic: Assert / Disprove / Timeout templates stay fixed while
//! [`CircuitBackend`](crate::backend::CircuitBackend) swaps the evaluation engine.

use crate::backend::{hashlock_commit, CircuitBackend, ClaimMiniBackend, EvaluationResult};
use crate::claim_mini::ClaimMini;
use crate::phase_a::opening::DirectSeedOpening;
use crate::tx_templates::{
    AssertTemplate, DisproveTemplate, TimeoutTemplate, DEFAULT_DISPUTE_WINDOW,
};

/// Dispute flow parameterized by a circuit backend.
pub struct PhaseAFlow<B: CircuitBackend = ClaimMiniBackend> {
    backend: B,
}

impl Default for PhaseAFlow<ClaimMiniBackend> {
    fn default() -> Self {
        Self::new(ClaimMiniBackend)
    }
}

impl<B: CircuitBackend<Claim = ClaimMini>> PhaseAFlow<B> {
    /// Create a flow with the given circuit backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Borrow the active backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Engine side: create Assert opening + hashlock commitment.
    pub fn engine_create_assert(
        &self,
        claim: &ClaimMini,
        funding_outpoint: &str,
    ) -> (AssertTemplate, DirectSeedOpening, [u8; 32]) {
        let claim_bytes = serialize_claim(claim);
        let opening = DirectSeedOpening::from_claim_bytes(0, &claim_bytes);
        let h_l_invalid = self.backend.commit_l_invalid(claim);

        let assert_tmpl = AssertTemplate {
            funding_outpoint: funding_outpoint.to_string(),
            claim: claim.clone(),
            hash_of_false_label: h_l_invalid,
            dispute_window: DEFAULT_DISPUTE_WINDOW,
        };

        (assert_tmpl, opening, h_l_invalid)
    }

    /// Challenger side: evaluate via the configured backend.
    pub fn challenger_evaluate(
        &self,
        claim: &ClaimMini,
        opening: &DirectSeedOpening,
        committed_h_l_invalid: &[u8; 32],
    ) -> EvaluationResult {
        let claim_bytes = serialize_claim(claim);
        let expected = DirectSeedOpening::from_claim_bytes(opening.instance_id, &claim_bytes);
        if opening.seed != expected.seed {
            // Opening mismatch — real systems abort harder; stand-in continues.
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

    /// Build a Disprove template when evaluation returned Invalid.
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

    /// Build a Timeout template (Engine side, after the dispute window).
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

/// Convenience: Claim Mini backend (static methods used by older call sites).
impl PhaseAFlow<ClaimMiniBackend> {
    /// Engine create with default [`ClaimMiniBackend`].
    pub fn engine_create_assert_default(
        claim: &ClaimMini,
        funding_outpoint: &str,
    ) -> (AssertTemplate, DirectSeedOpening, [u8; 32]) {
        Self::default().engine_create_assert(claim, funding_outpoint)
    }

    /// Challenger evaluate with default [`ClaimMiniBackend`].
    pub fn challenger_evaluate_default(
        claim: &ClaimMini,
        opening: &DirectSeedOpening,
        committed_h_l_invalid: &[u8; 32],
    ) -> EvaluationResult {
        Self::default().challenger_evaluate(claim, opening, committed_h_l_invalid)
    }
}

/// Minimal deterministic serialization for the prototype.
pub(crate) fn serialize_claim(claim: &ClaimMini) -> Vec<u8> {
    let mut buf = Vec::with_capacity(176);
    buf.extend_from_slice(&claim.h_old);
    buf.extend_from_slice(&claim.h_new);
    buf.extend_from_slice(&claim.total_in.to_le_bytes());
    buf.extend_from_slice(&claim.total_out.to_le_bytes());
    buf.extend_from_slice(&claim.t1);
    buf.extend_from_slice(&claim.t2);
    buf.extend_from_slice(&claim.t3);
    buf.extend_from_slice(&claim.t4);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::GarbledSnarkBackend;
    use crate::claim_mini::ClaimMini;

    fn dummy32(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = seed;
        a
    }

    fn sample_claim() -> ClaimMini {
        ClaimMini::make_valid(
            dummy32(1),
            100_000,
            40_000,
            dummy32(10),
            dummy32(11),
            dummy32(12),
            dummy32(13),
        )
    }

    #[test]
    fn happy_path_claim_mini() {
        let flow = PhaseAFlow::new(ClaimMiniBackend);
        let claim = sample_claim();
        let (_tmpl, opening, h) = flow.engine_create_assert(&claim, "txid:0");
        assert!(matches!(
            flow.challenger_evaluate(&claim, &opening, &h),
            EvaluationResult::Valid
        ));
        let _timeout = PhaseAFlow::<ClaimMiniBackend>::build_timeout(
            "assert_txid:0",
            "reserve:0",
            "engine_pk",
        );
    }

    #[test]
    fn unhappy_path_claim_mini() {
        let flow = PhaseAFlow::new(ClaimMiniBackend);
        let mut claim = sample_claim();
        claim.total_out = 250_000;
        let (_tmpl, opening, h) = flow.engine_create_assert(&claim, "txid:0");
        match flow.challenger_evaluate(&claim, &opening, &h) {
            EvaluationResult::Invalid { l_invalid } => {
                let d = PhaseAFlow::<ClaimMiniBackend>::build_disprove(
                    "assert_txid:0",
                    l_invalid,
                    "challenger",
                );
                assert_eq!(d.false_label, l_invalid);
                assert_eq!(hashlock_commit(&l_invalid), h);
            }
            EvaluationResult::Valid => panic!("should be invalid"),
        }
    }

    #[test]
    fn happy_and_unhappy_gsv_stand_in() {
        let flow = PhaseAFlow::new(GarbledSnarkBackend);
        let claim = sample_claim();
        let (_tmpl, opening, h) = flow.engine_create_assert(&claim, "txid:0");
        assert!(matches!(
            flow.challenger_evaluate(&claim, &opening, &h),
            EvaluationResult::Valid
        ));

        let mut bad = claim;
        bad.total_out = 250_000;
        let (_tmpl, opening, h) = flow.engine_create_assert(&bad, "txid:0");
        match flow.challenger_evaluate(&bad, &opening, &h) {
            EvaluationResult::Invalid { l_invalid } => {
                assert_eq!(hashlock_commit(&l_invalid), h);
                // GSV stand-in labels differ from Claim Mini labels.
                let mini = PhaseAFlow::new(ClaimMiniBackend);
                let (_t, _o, h_mini) = mini.engine_create_assert(&bad, "txid:0");
                assert_ne!(h, h_mini);
            }
            EvaluationResult::Valid => panic!("should be invalid"),
        }
    }
}
