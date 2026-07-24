//! Phase C+ – garbled Groth16 verifier Evaluate (`garbled_groth16::verify`).
//!
//! Mirrors upstream `examples/gsv_garble.rs` with Beacon hashlock labels:
//! `L_invalid = expand(output.label0)`, `L_valid = expand(output.label1)`.
//!
//! Intended for `--release` runs. Full BN254 verify is heavy (minutes, GBs peak).

use std::thread;

use crossbeam::channel;
use garbled_snark_verifier::ark::{
    self, CircuitSpecificSetupSNARK, SNARK, UniformRand,
};
use garbled_snark_verifier::ciphertext_hasher::Blake3AccumulatingHash;
use garbled_snark_verifier::circuit::{
    CircuitBuilder, StreamingResult,
    modes::{EvaluateMode, GarbleMode},
};
use garbled_snark_verifier::garbled_groth16::{self, EvaluatorInput, GarblerInput};
use garbled_snark_verifier::hashers::{Blake3Hasher, GateHasher};
use garbled_snark_verifier::test_utils::DummyCircuit;
use garbled_snark_verifier::{EvaluatedWire, GarbledWire};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::backend::{hashlock_commit, EvaluationResult};
use crate::phase_c::labels::{expand_label_bytes, seed_from_label_material};

/// Live-wire capacity for the Groth16 verifier gadget (upstream default).
pub const GROTH16_CAPACITY: usize = 150_000;

/// Constraint parameter `k` → `2^k` constraints in [`DummyCircuit`].
pub const DEFAULT_K: u32 = 6;

/// Everything the challenger needs to Evaluate after Assert.
#[derive(Clone)]
pub struct Groth16AssertBundle {
    pub seed: u64,
    pub k: u32,
    pub l_invalid: [u8; 32],
    pub l_valid: [u8; 32],
    pub ciphertext_hash: [u8; 32],
    pub true_wire: u128,
    pub false_wire: u128,
    /// Whether the posted proof is expected to verify (honest Engine).
    pub proof_should_verify: bool,
    // Heavy fields kept for Evaluate (not serialized for now).
    pub(crate) vk: ark::VerifyingKey<ark::Bn254>,
    pub(crate) proof: ark::Proof<ark::Bn254>,
    pub(crate) public: Vec<ark::Fr>,
    pub(crate) input_wire_values: Vec<GarbledWire>,
    pub(crate) garbler_input: GarblerInput,
}

/// Prove a tiny DummyCircuit and garble the BN254 verifier.
///
/// When `break_proof` is true, public inputs are corrupted so Evaluate yields
/// the invalid output label (Disprove path).
pub fn setup_garble(
    label_material: &[u8; 32],
    break_proof: bool,
    k: u32,
) -> Result<Groth16AssertBundle, String> {
    let seed = seed_from_label_material(label_material);
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0xC0FF_EE00_u64);

    let a = ark::Fr::rand(&mut rng);
    let b = ark::Fr::rand(&mut rng);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(a),
        b: Some(b),
        num_variables: 10,
        num_constraints: 1 << k,
    };

    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng)
        .map_err(|e| format!("groth16 setup: {e}"))?;
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|e| format!("groth16 prove: {e}"))?;

    let mut public = vec![a * b];
    if break_proof {
        public[0] += ark::Fr::from(1u64);
    }

    let garbler_input = GarblerInput {
        public_params_len: public.len(),
        vk: vk.clone(),
    };

    let ciphertext_hasher = Blake3AccumulatingHash::default();
    let garbling_result: StreamingResult<GarbleMode<Blake3Hasher, _>, _, GarbledWire> =
        CircuitBuilder::streaming_garbling(
            garbler_input.clone(),
            GROTH16_CAPACITY,
            seed,
            ciphertext_hasher,
            garbled_groth16::verify,
        );

    let out = garbling_result.output_labels().clone();
    let l_invalid = expand_label_bytes(&out.label0.to_bytes());
    let l_valid = expand_label_bytes(&out.label1.to_bytes());

    Ok(Groth16AssertBundle {
        seed,
        k,
        l_invalid,
        l_valid,
        ciphertext_hash: garbling_result.ciphertext_handler_result,
        true_wire: garbling_result.true_wire_constant.select(true).to_u128(),
        false_wire: garbling_result.false_wire_constant.select(false).to_u128(),
        proof_should_verify: !break_proof,
        vk,
        proof,
        public,
        input_wire_values: garbling_result.input_wire_values,
        garbler_input,
    })
}

/// Hashlock commitment for the Disprove leaf.
#[must_use]
pub fn commit_from_bundle(bundle: &Groth16AssertBundle) -> [u8; 32] {
    hashlock_commit(&bundle.l_invalid)
}

/// Re-garble (stream ciphertexts) + Evaluate the posted proof.
pub fn evaluate_bundle(bundle: &Groth16AssertBundle) -> Result<EvaluationResult, String> {
    let gate_hasher = {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(bundle.seed);
        Blake3Hasher::from_rng(&mut rng)
    };

    let (ct_sender, ct_receiver) = channel::unbounded();
    let (proxy_sender, proxy_receiver) = channel::unbounded();

    let expected_hash = bundle.ciphertext_hash;
    let hash_thread = thread::spawn(move || {
        let mut hasher = Blake3AccumulatingHash::default();
        while let Ok(ct) = ct_receiver.recv() {
            proxy_sender.send(ct).map_err(|_| ())?;
            hasher.update(ct);
        }
        Ok::<_, ()>(hasher.finalize())
    });

    let garbler_input = bundle.garbler_input.clone();
    let seed = bundle.seed;
    let garbler = thread::spawn(move || {
        let _: StreamingResult<GarbleMode<Blake3Hasher, _>, _, GarbledWire> =
            CircuitBuilder::streaming_garbling_with_sender(
                garbler_input,
                GROTH16_CAPACITY,
                seed,
                ct_sender,
                garbled_groth16::verify,
            );
    });

    let eval_input = EvaluatorInput::new(
        bundle.public.clone(),
        bundle.proof.clone(),
        bundle.vk.clone(),
        bundle.input_wire_values.clone(),
    );

    let evaluate_result: StreamingResult<EvaluateMode<Blake3Hasher, _>, _, EvaluatedWire> =
        CircuitBuilder::streaming_evaluation(
            eval_input,
            GROTH16_CAPACITY,
            bundle.true_wire,
            bundle.false_wire,
            gate_hasher,
            proxy_receiver,
            garbled_groth16::verify,
        );

    garbler
        .join()
        .map_err(|_| "garbler thread panicked".to_string())?;
    let got_hash = hash_thread
        .join()
        .map_err(|_| "hash thread panicked".to_string())?
        .map_err(|_| "ciphertext proxy closed early".to_string())?;
    if got_hash != expected_hash {
        return Err("ciphertext hash mismatch (garble/evaluate desync)".into());
    }

    let EvaluatedWire {
        active_label,
        value: is_proof_correct,
    } = evaluate_result.output_value;

    let active = expand_label_bytes(&active_label.to_bytes());
    if is_proof_correct {
        if active != bundle.l_valid {
            return Err("valid proof but active label ≠ L_valid".into());
        }
        Ok(EvaluationResult::Valid)
    } else {
        if active != bundle.l_invalid {
            return Err("invalid proof but active label ≠ L_invalid".into());
        }
        Ok(EvaluationResult::Invalid {
            l_invalid: bundle.l_invalid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ark_proof_roundtrip_smoke() {
        // Fast: ark prove/verify only (no garble).
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let a = ark::Fr::rand(&mut rng);
        let b = ark::Fr::rand(&mut rng);
        let circuit = DummyCircuit::<ark::Fr> {
            a: Some(a),
            b: Some(b),
            num_variables: 10,
            num_constraints: 1 << 4,
        };
        let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).unwrap();
        let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let public = vec![a * b];
        assert!(
            ark::Groth16::<ark::Bn254>::verify(&vk, &public, &proof).unwrap()
        );
    }

    #[test]
    #[ignore = "Phase C+ full garble/evaluate — run with: cargo test -F gsv --release -- --ignored groth16_garble_evaluate"]
    fn groth16_garble_evaluate_valid_and_invalid() {
        let material = [0xCE; 32];
        let honest = setup_garble(&material, false, 4).expect("setup");
        assert!(matches!(
            evaluate_bundle(&honest).expect("eval"),
            EvaluationResult::Valid
        ));

        let cheat = setup_garble(&material, true, 4).expect("setup cheat");
        match evaluate_bundle(&cheat).expect("eval cheat") {
            EvaluationResult::Invalid { l_invalid } => {
                assert_eq!(hashlock_commit(&l_invalid), commit_from_bundle(&cheat));
            }
            EvaluationResult::Valid => panic!("expected invalid"),
        }
    }
}
