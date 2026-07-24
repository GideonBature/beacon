//! Pluggable circuit backends.
//!
//! The on-chain Assert / Disprove / Timeout graph stays fixed. Only the
//! off-chain evaluation engine that produces `L_invalid` (or not) changes.
//!
//! ```text
//! CircuitBackend
//! ├── ClaimMiniBackend     ← Phase A (works today)
//! └── GarbledSnarkBackend  ← BitVM3 path (stand-in + integration contract)
//! ```
//!
//! Target production engine:
//! <https://github.com/BitVM/garbled-snark-verifier>

mod claim_mini;
mod gsv;

pub use claim_mini::ClaimMiniBackend;
pub use gsv::GarbledSnarkBackend;

use crate::phase_a::opening::DirectSeedOpening;
use sha2::{Digest, Sha256};

/// Result of evaluating an Assert with a [`CircuitBackend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationResult {
    /// Claim is valid – Engine may later timeout.
    Valid,
    /// Claim is invalid – challenger obtained `L*` and can Disprove.
    Invalid { l_invalid: [u8; 32] },
}

/// On-chain hashlock commitment: `H(L_invalid) = SHA256(L*)`.
///
/// Must match the Disprove leaf (`OP_SHA256 <H> OP_EQUALVERIFY`).
#[must_use]
pub fn hashlock_commit(l_invalid: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(l_invalid);
    hasher.finalize().into()
}

/// Off-chain circuit engine used by the dispute flow.
pub trait CircuitBackend {
    /// Public claim / statement type this backend evaluates.
    type Claim;

    /// Short name for logs / CLI (`claim-mini`, `garbled-snark-verifier`, …).
    fn name(&self) -> &'static str;

    /// Setup / assert-time commitment published in the Disprove hashlock.
    fn commit_l_invalid(&self, claim: &Self::Claim) -> [u8; 32];

    /// Challenger evaluation after recovering the Assert opening.
    ///
    /// On invalid claims, returns [`EvaluationResult::Invalid`] whose
    /// `l_invalid` satisfies `hashlock_commit(l_invalid) == commit_l_invalid(claim)`.
    fn evaluate(&self, claim: &Self::Claim, opening: &DirectSeedOpening) -> EvaluationResult;
}
