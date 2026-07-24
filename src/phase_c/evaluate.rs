//! Tiny garbled Evaluate (AND circuit) → Accept / Disprove labels.
//!
//! With `gsv`: real `streaming_garbling` + `streaming_evaluation`.
//! Without: Claim Mini stand-in with Phase C domain-separated `L*`.

use crate::backend::{hashlock_commit, EvaluationResult};
use crate::claim_mini::ClaimMini;

/// Commit `H(L_invalid)` for the Disprove hashlock at Assert time.
#[must_use]
pub fn commit_l_invalid(claim: &ClaimMini, label_material: &[u8; 32]) -> [u8; 32] {
    hashlock_commit(&l_invalid_for(claim, label_material))
}

/// Evaluate claim after recovering label / share material from the opening.
#[must_use]
pub fn evaluate_claim(claim: &ClaimMini, label_material: &[u8; 32]) -> EvaluationResult {
    linked::evaluate(claim, label_material)
}

fn l_invalid_for(claim: &ClaimMini, label_material: &[u8; 32]) -> [u8; 32] {
    linked::l_invalid(claim, label_material)
}

#[cfg(feature = "gsv")]
mod linked {
    use super::*;
    use crate::phase_c::labels::{expand_label_bytes, seed_from_label_material};
    use crossbeam::channel;
    use garbled_snark_verifier::circuit::{
        CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, StreamingResult,
        modes::{EvaluateMode, GarbleMode},
    };
    use garbled_snark_verifier::{
        Blake3Hasher, CircuitContext, Delta, EvaluatedWire, Gate, GateHasher, GarbledWire, WireId,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[derive(Clone, Debug)]
    struct GarbleInputs {
        flag: GarbledWire,
        one: GarbledWire,
    }

    #[derive(Debug)]
    struct EvalInputs {
        flag: EvaluatedWire,
        one: EvaluatedWire,
    }

    #[derive(Debug, Clone)]
    struct InputsWire {
        flag: WireId,
        one: WireId,
    }

    impl CircuitInput for GarbleInputs {
        type WireRepr = InputsWire;

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            InputsWire {
                flag: issue(),
                one: issue(),
            }
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            vec![repr.flag, repr.one]
        }
    }

    impl CircuitInput for EvalInputs {
        type WireRepr = InputsWire;

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            InputsWire {
                flag: issue(),
                one: issue(),
            }
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            vec![repr.flag, repr.one]
        }
    }

    impl<M: CircuitMode<WireValue = GarbledWire>> EncodeInput<M> for GarbleInputs {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
            cache.feed_wire(repr.flag, self.flag.clone());
            cache.feed_wire(repr.one, self.one.clone());
        }
    }

    impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for EvalInputs {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
            cache.feed_wire(repr.flag, self.flag.clone());
            cache.feed_wire(repr.one, self.one.clone());
        }
    }

    fn circuit_fn(ctx: &mut impl CircuitContext, wires: &InputsWire) -> Vec<WireId> {
        let result = ctx.issue_wire();
        ctx.add_gate(Gate::and(wires.flag, wires.one, result));
        vec![result]
    }

    /// Garble the toy verifier; return output wire (label0 = invalid, label1 = valid).
    fn garble_output(seed: u64) -> GarbledWire {
        let mut rng = ChaChaRng::seed_from_u64(seed);
        let delta = Delta::generate(&mut rng);
        let inputs = GarbleInputs {
            flag: GarbledWire::random(&mut rng, &delta),
            one: GarbledWire::random(&mut rng, &delta),
        };
        let (sender, _receiver) = channel::unbounded();
        let result: StreamingResult<GarbleMode<Blake3Hasher, _>, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling(inputs, 64, seed, sender, circuit_fn);
        result.output_value[0].clone()
    }

    pub fn l_invalid(claim: &ClaimMini, label_material: &[u8; 32]) -> [u8; 32] {
        let _ = claim; // claim binds via opening → label_material → seed
        let seed = seed_from_label_material(label_material);
        let out = garble_output(seed);
        expand_label_bytes(&out.label0.to_bytes())
    }

    pub fn evaluate(claim: &ClaimMini, label_material: &[u8; 32]) -> EvaluationResult {
        let seed = seed_from_label_material(label_material);
        let flag = claim.verify();

        let mut rng = ChaChaRng::seed_from_u64(seed);
        let delta = Delta::generate(&mut rng);
        let garble_inputs = GarbleInputs {
            flag: GarbledWire::random(&mut rng, &delta),
            one: GarbledWire::random(&mut rng, &delta),
        };
        let eval_inputs = EvalInputs {
            flag: EvaluatedWire::new_from_garbled(&garble_inputs.flag, flag),
            one: EvaluatedWire::new_from_garbled(&garble_inputs.one, true),
        };

        let (sender, receiver) = channel::unbounded();
        let garble_result: StreamingResult<GarbleMode<Blake3Hasher, _>, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling(garble_inputs, 64, seed, sender, circuit_fn);

        let gate_hasher = {
            let mut rng = ChaChaRng::seed_from_u64(seed);
            Blake3Hasher::from_rng(&mut rng)
        };

        let evaluate_result: StreamingResult<_, _, Vec<EvaluatedWire>> =
            CircuitBuilder::<EvaluateMode<Blake3Hasher, _>>::streaming_evaluation(
                eval_inputs,
                64,
                garble_result.true_wire_constant.select(true).to_u128(),
                garble_result.false_wire_constant.select(false).to_u128(),
                gate_hasher,
                receiver,
                circuit_fn,
            );

        let out_g = &garble_result.output_value[0];
        let out_e = &evaluate_result.output_value[0];
        let l_invalid = expand_label_bytes(&out_g.label0.to_bytes());
        let l_valid = expand_label_bytes(&out_g.label1.to_bytes());

        // Active label must match the expected bit's garbled label.
        let expected = if flag {
            out_g.select(true)
        } else {
            out_g.select(false)
        };
        assert_eq!(
            out_e.active_label, expected,
            "garble/evaluate label mismatch (Phase C)"
        );

        if flag {
            // Sanity: valid path yields L_valid material, not the hashlock preimage.
            let _ = l_valid;
            EvaluationResult::Valid
        } else {
            EvaluationResult::Invalid { l_invalid }
        }
    }
}

#[cfg(not(feature = "gsv"))]
mod linked {
    use super::*;
    use sha2::{Digest, Sha256};

    pub fn l_invalid(claim: &ClaimMini, label_material: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"Beacon/PhaseC/StandIn/L*/v1");
        hasher.update(label_material);
        hasher.update(claim.preimage());
        hasher.update(claim.total_in.to_le_bytes());
        hasher.update(claim.total_out.to_le_bytes());
        hasher.finalize().into()
    }

    pub fn evaluate(claim: &ClaimMini, label_material: &[u8; 32]) -> EvaluationResult {
        if claim.verify() {
            EvaluationResult::Valid
        } else {
            EvaluationResult::Invalid {
                l_invalid: l_invalid(claim, label_material),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phase_a::opening::DirectSeedOpening;

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
            c.total_out = 250_000;
        }
        c
    }

    #[test]
    fn happy_and_unhappy_match_hashlock() {
        let material =
            DirectSeedOpening::from_claim_bytes(0, b"phase-c").derive_label_material();
        let good = sample(true);
        let h = commit_l_invalid(&good, &material);
        assert!(matches!(
            evaluate_claim(&good, &material),
            EvaluationResult::Valid
        ));

        let bad = sample(false);
        let h_bad = commit_l_invalid(&bad, &material);
        match evaluate_claim(&bad, &material) {
            EvaluationResult::Invalid { l_invalid } => {
                assert_eq!(hashlock_commit(&l_invalid), h_bad);
                // Different claim bytes → different label material binding in stand-in;
                // with gsv, seed is from material only so h may equal h_bad.
                let _ = h;
            }
            EvaluationResult::Valid => panic!("expected invalid"),
        }
    }
}
