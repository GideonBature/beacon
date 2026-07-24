//! Garbled SNARK verifier backend (BitVM3 path).
//!
//! With the `gsv` feature this module links
//! [`garbled-snark-verifier`](https://github.com/BitVM/garbled-snark-verifier)
//! via Cargo git dependency. Full garbled Groth16 evaluate remains a heavy
//! Phase C job; Phase A still maps Claim Mini validity onto hashlock labels
//! while calling into the real crate for Execute-mode smoke evaluation.

use super::{hashlock_commit, CircuitBackend, EvaluationResult};
use crate::claim_mini::ClaimMini;
use crate::phase_a::opening::DirectSeedOpening;

#[cfg(feature = "gsv")]
mod linked {
    use super::*;
    use garbled_snark_verifier::circuit::{
        CircuitBuilder, CircuitInput, EncodeInput, StreamingResult,
    };
    use garbled_snark_verifier::{CircuitContext, Gate, WireId};
    use sha2::{Digest, Sha256};

    /// `L_invalid` for the Taproot hashlock (32 bytes).
    pub fn l_invalid(claim: &ClaimMini) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"GSV/L_invalid/v1");
        hasher.update(claim.preimage());
        hasher.update(claim.total_in.to_le_bytes());
        hasher.update(claim.total_out.to_le_bytes());
        hasher.update(claim.h_new);
        // Mix a bit of GSV-linked environment so the path is distinct from
        // ClaimMiniBackend even when validity rules match.
        hasher.update([u8::from(garbled_snark_verifier::hardware_aes_available())]);
        hasher.finalize().into()
    }

    pub fn evaluate(claim: &ClaimMini, opening: &DirectSeedOpening) -> EvaluationResult {
        // Recover label material (Phase A seed stand-in for wide labels).
        let _labels = opening.derive_label_material();

        // Prove the GSV crate is callable: tiny AND circuit via Execute mode.
        // (Full Garble/Evaluate of Groth16 verify is Phase C / release-only.)
        let _ = smoke_and_circuit(claim.verify());

        if claim.verify() {
            EvaluationResult::Valid
        } else {
            EvaluationResult::Invalid {
                l_invalid: l_invalid(claim),
            }
        }
    }

    /// Minimal `CircuitBuilder::streaming_execute` against the linked crate.
    pub fn smoke_and_circuit(flag: bool) -> bool {
        #[derive(Clone)]
        struct Inputs {
            flag: bool,
            bit: bool,
        }

        struct InputsWire {
            flag: WireId,
            bit: WireId,
        }

        impl CircuitInput for Inputs {
            type WireRepr = InputsWire;

            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                InputsWire {
                    flag: issue(),
                    bit: issue(),
                }
            }

            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                vec![repr.flag, repr.bit]
            }
        }

        impl<M: garbled_snark_verifier::circuit::CircuitMode<WireValue = bool>> EncodeInput<M>
            for Inputs
        {
            fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
                cache.feed_wire(repr.flag, self.flag);
                cache.feed_wire(repr.bit, self.bit);
            }
        }

        let inputs = Inputs { flag, bit: true };

        let output: StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, wires| {
                let result = root.issue_wire();
                root.add_gate(Gate::and(wires.flag, wires.bit, result));
                vec![result]
            });

        output.output_value[0]
    }
}

#[cfg(not(feature = "gsv"))]
mod linked {
    use super::*;
    use sha2::{Digest, Sha256};

    pub fn l_invalid(claim: &ClaimMini) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"GSV/L_invalid/v1");
        hasher.update(claim.preimage());
        hasher.update(claim.total_in.to_le_bytes());
        hasher.update(claim.total_out.to_le_bytes());
        hasher.update(claim.h_new);
        hasher.finalize().into()
    }

    pub fn evaluate(claim: &ClaimMini, opening: &DirectSeedOpening) -> EvaluationResult {
        let _ = opening;
        if claim.verify() {
            EvaluationResult::Valid
        } else {
            EvaluationResult::Invalid {
                l_invalid: l_invalid(claim),
            }
        }
    }
}

/// BitVM3 backend backed by `garbled-snark-verifier` when `gsv` is enabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct GarbledSnarkBackend;

impl GarbledSnarkBackend {
    /// Whether this build linked the real GSV crate.
    #[must_use]
    pub const fn is_linked() -> bool {
        cfg!(feature = "gsv")
    }
}

impl CircuitBackend for GarbledSnarkBackend {
    type Claim = ClaimMini;

    fn name(&self) -> &'static str {
        if Self::is_linked() {
            "garbled-snark-verifier"
        } else {
            "garbled-snark-verifier (stand-in)"
        }
    }

    fn commit_l_invalid(&self, claim: &Self::Claim) -> [u8; 32] {
        hashlock_commit(&linked::l_invalid(claim))
    }

    fn evaluate(&self, claim: &Self::Claim, opening: &DirectSeedOpening) -> EvaluationResult {
        linked::evaluate(claim, opening)
    }
}

#[cfg(all(test, feature = "gsv"))]
mod tests {
    use super::*;
    use crate::backend::CircuitBackend;

    #[test]
    fn linked_smoke_and_hashlock() {
        assert!(GarbledSnarkBackend::is_linked());
        assert!(linked::smoke_and_circuit(true));
        assert!(!linked::smoke_and_circuit(false));

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
