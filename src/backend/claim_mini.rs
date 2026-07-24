//! Phase A circuit backend: evaluate [`ClaimMini`](crate::ClaimMini) directly.

use super::{hashlock_commit, CircuitBackend, EvaluationResult};
use crate::claim_mini::{ClaimMini, OutputWire};
use crate::phase_a::opening::DirectSeedOpening;

/// Lightweight backend used by Phase A demos and tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClaimMiniBackend;

impl CircuitBackend for ClaimMiniBackend {
    type Claim = ClaimMini;

    fn name(&self) -> &'static str {
        "claim-mini"
    }

    fn commit_l_invalid(&self, claim: &Self::Claim) -> [u8; 32] {
        let wire = OutputWire::from_claim(claim);
        hashlock_commit(&wire.false_label_placeholder)
    }

    fn evaluate(&self, claim: &Self::Claim, _opening: &DirectSeedOpening) -> EvaluationResult {
        let wire = OutputWire::from_claim(claim);
        if wire.value {
            EvaluationResult::Valid
        } else {
            EvaluationResult::Invalid {
                l_invalid: wire.false_label_placeholder,
            }
        }
    }
}
