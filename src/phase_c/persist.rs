//! Persist tiny AND garble streams and Evaluate from disk (`gsv`).
//!
//! Engine garbles once into [`CiphertextStore`]; challenger verifies the
//! Blake3-accumulating ciphertext hash and evaluates without re-garbling.

use crossbeam::channel;
use garbled_snark_verifier::circuit::{
    ciphertext_source::{CiphertextSource, FileSource},
    CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, StreamingResult,
    modes::{EvaluateMode, GarbleMode},
};
use garbled_snark_verifier::cut_and_choose::FileCiphertextHandler;
use garbled_snark_verifier::{
    Blake3Hasher, CircuitContext, Delta, EvaluatedWire, Gate, GateHasher, GarbledWire, WireId, S,
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};

use crate::backend::EvaluationResult;
use crate::claim_mini::ClaimMini;
use crate::phase_c::ciphertext_store::{
    CiphertextMeta, CiphertextStore, StoreError, HASH_ALG_BLAKE3_ACCUM, META_FORMAT_V1,
};
use crate::phase_c::labels::{expand_label_bytes, seed_from_label_material};

/// Eval package: labels + wires needed after CT is on disk (no Engine RAM).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndEvalPackage {
    pub meta: CiphertextMeta,
    /// Garbled input wire labels (16-byte BE each): flag then one.
    #[serde(with = "hex_bytes")]
    pub input_wire_bytes: Vec<u8>,
}

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

fn encode_garbled_wire(w: &GarbledWire) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&w.label0.to_bytes());
    out[16..].copy_from_slice(&w.label1.to_bytes());
    out
}

fn decode_garbled_wire(bytes: &[u8]) -> Result<GarbledWire, StoreError> {
    if bytes.len() != 32 {
        return Err(StoreError::BadMeta("garbled wire length"));
    }
    let mut l0 = [0u8; 16];
    let mut l1 = [0u8; 16];
    l0.copy_from_slice(&bytes[..16]);
    l1.copy_from_slice(&bytes[16..]);
    Ok(GarbledWire {
        label0: S::from_bytes(l0),
        label1: S::from_bytes(l1),
    })
}

/// Garble the toy AND once, write CT to disk, return eval package + hashlock material.
pub fn garble_and_to_store(
    store: &CiphertextStore,
    instance_id: u32,
    label_material: &[u8; 32],
) -> Result<AndEvalPackage, StoreError> {
    let seed = seed_from_label_material(label_material);
    let mut rng = ChaChaRng::seed_from_u64(seed);
    let delta = Delta::generate(&mut rng);
    let inputs = GarbleInputs {
        flag: GarbledWire::random(&mut rng, &delta),
        one: GarbledWire::random(&mut rng, &delta),
    };

    let stream_path = store.stream_path(instance_id);
    let handler = FileCiphertextHandler::create(stream_path.clone(), None)?;
    let result: StreamingResult<GarbleMode<Blake3Hasher, _>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(inputs.clone(), 64, seed, handler, circuit_fn);

    let out = &result.output_value[0];
    let l_invalid = expand_label_bytes(&out.label0.to_bytes());
    let l_valid = expand_label_bytes(&out.label1.to_bytes());
    let ciphertext_hash = result.ciphertext_handler_result;

    let mut input_wire_bytes = Vec::with_capacity(64);
    input_wire_bytes.extend_from_slice(&encode_garbled_wire(&inputs.flag));
    input_wire_bytes.extend_from_slice(&encode_garbled_wire(&inputs.one));

    let meta = CiphertextMeta {
        format: META_FORMAT_V1,
        instance_id,
        ciphertext_hash,
        hash_alg: HASH_ALG_BLAKE3_ACCUM.into(),
        seed,
        true_wire: result.true_wire_constant.select(true).to_u128(),
        false_wire: result.false_wire_constant.select(false).to_u128(),
        l_invalid,
        l_valid,
        stream_file: format!("gc_{instance_id}.bin"),
    };
    store.write_meta(&meta)?;

    // Also persist the eval package next to meta for challenger reload.
    let pkg = AndEvalPackage {
        meta: meta.clone(),
        input_wire_bytes,
    };
    write_package(store, &pkg)?;
    Ok(pkg)
}

fn package_path(store: &CiphertextStore, instance_id: u32) -> std::path::PathBuf {
    store.root().join(format!("gc_{instance_id}.pkg.json"))
}

fn write_package(store: &CiphertextStore, pkg: &AndEvalPackage) -> Result<(), StoreError> {
    let path = package_path(store, pkg.meta.instance_id);
    let tmp = path.with_extension("pkg.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(pkg)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Load eval package written by [`garble_and_to_store`].
pub fn load_and_package(
    store: &CiphertextStore,
    instance_id: u32,
) -> Result<AndEvalPackage, StoreError> {
    let path = package_path(store, instance_id);
    if !path.exists() {
        return Err(StoreError::NotFound(instance_id));
    }
    let pkg: AndEvalPackage = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(pkg)
}

/// Verify CT hash then Evaluate from disk (no re-garble).
pub fn evaluate_and_from_store(
    store: &CiphertextStore,
    claim: &ClaimMini,
    instance_id: u32,
) -> Result<EvaluationResult, StoreError> {
    let (meta, stream_path) = store.open_verified(instance_id)?;
    let pkg = load_and_package(store, instance_id)?;
    if pkg.meta.ciphertext_hash != meta.ciphertext_hash {
        return Err(StoreError::BadMeta("package/meta hash mismatch"));
    }
    if pkg.input_wire_bytes.len() != 64 {
        return Err(StoreError::BadMeta("input wire bytes"));
    }
    let flag = decode_garbled_wire(&pkg.input_wire_bytes[..32])?;
    let one = decode_garbled_wire(&pkg.input_wire_bytes[32..])?;
    let flag_bit = claim.verify();
    let eval_inputs = EvalInputs {
        flag: EvaluatedWire::new_from_garbled(&flag, flag_bit),
        one: EvaluatedWire::new_from_garbled(&one, true),
    };

    let gate_hasher = {
        let mut rng = ChaChaRng::seed_from_u64(meta.seed);
        Blake3Hasher::from_rng(&mut rng)
    };

    // Stream from disk into evaluation via a channel (FileSource is pull-based;
    // bridge so streaming_evaluation can consume).
    let (tx, rx) = channel::unbounded();
    let path_for_thread = stream_path.clone();
    let expected = meta.ciphertext_hash;
    let feeder = std::thread::spawn(move || -> Result<[u8; 32], ()> {
        let mut src = FileSource::from_path(path_for_thread).map_err(|_| ())?;
        while let Some(ct) = src.recv() {
            tx.send(ct).map_err(|_| ())?;
        }
        drop(tx);
        Ok(src.finalize())
    });

    let evaluate_result: StreamingResult<_, _, Vec<EvaluatedWire>> =
        CircuitBuilder::<EvaluateMode<Blake3Hasher, _>>::streaming_evaluation(
            eval_inputs,
            64,
            meta.true_wire,
            meta.false_wire,
            gate_hasher,
            rx,
            circuit_fn,
        );

    let got_hash = feeder
        .join()
        .map_err(|_| StoreError::BadMeta("feeder panicked"))?
        .map_err(|_| StoreError::BadMeta("feeder io"))?;
    if got_hash != expected {
        return Err(StoreError::HashMismatch {
            instance_id,
            expected,
            got: got_hash,
        });
    }

    let out_e = &evaluate_result.output_value[0];
    let active = expand_label_bytes(&out_e.active_label.to_bytes());
    if flag_bit {
        if active != meta.l_valid {
            return Err(StoreError::BadMeta("active ≠ L_valid"));
        }
        Ok(EvaluationResult::Valid)
    } else {
        if active != meta.l_invalid {
            return Err(StoreError::BadMeta("active ≠ L_invalid"));
        }
        Ok(EvaluationResult::Invalid {
            l_invalid: meta.l_invalid,
        })
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::hashlock_commit;
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
    fn persist_roundtrip_valid_and_invalid() {
        let dir = std::env::temp_dir().join(format!(
            "beacon-and-persist-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = CiphertextStore::open(&dir).unwrap();
        let material =
            DirectSeedOpening::from_claim_bytes(0, b"persist-c").derive_label_material();

        let pkg = garble_and_to_store(&store, 0, &material).unwrap();
        assert_eq!(pkg.meta.hash_alg, HASH_ALG_BLAKE3_ACCUM);
        store.verify(0).unwrap();

        let good = sample(true);
        assert!(matches!(
            evaluate_and_from_store(&store, &good, 0).unwrap(),
            EvaluationResult::Valid
        ));

        let bad = sample(false);
        match evaluate_and_from_store(&store, &bad, 0).unwrap() {
            EvaluationResult::Invalid { l_invalid } => {
                assert_eq!(l_invalid, pkg.meta.l_invalid);
                assert_eq!(hashlock_commit(&l_invalid), hashlock_commit(&pkg.meta.l_invalid));
            }
            EvaluationResult::Valid => panic!("expected invalid"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
