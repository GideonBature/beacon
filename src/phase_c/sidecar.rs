//! Phase C+ evaluation sidecar: VK / proof / publics / input wires on disk.
//!
//! Paired with [`CiphertextStore`] CT streams so a challenger can Evaluate
//! without keeping a live Engine `Groth16AssertBundle` in RAM.

use garbled_snark_verifier::ark::{self, ark_serialize::{CanonicalDeserialize, CanonicalSerialize}};
use garbled_snark_verifier::garbled_groth16::GarblerInput;
use garbled_snark_verifier::{GarbledWire, S};

use crate::phase_c::ciphertext_store::{CiphertextStore, StoreError};
use crate::phase_c::groth16::Groth16AssertBundle;

/// Sidecar wire magic: Beacon Eval Ark.
pub const SIDECAR_MAGIC: &[u8; 4] = b"BEAE";
pub const SIDECAR_FORMAT_V1: u8 = 1;

/// Disk package for Evaluate (heavy ark / wire fields).
#[derive(Clone)]
pub struct Groth16EvalSidecar {
    pub k: u32,
    pub proof_should_verify: bool,
    pub vk: ark::VerifyingKey<ark::Bn254>,
    pub proof: ark::Proof<ark::Bn254>,
    pub public: Vec<ark::Fr>,
    pub input_wire_values: Vec<GarbledWire>,
    pub garbler_input: GarblerInput,
}

impl Groth16EvalSidecar {
    pub fn from_bundle(bundle: &Groth16AssertBundle) -> Self {
        Self {
            k: bundle.k,
            proof_should_verify: bundle.proof_should_verify,
            vk: bundle.vk.clone(),
            proof: bundle.proof.clone(),
            public: bundle.public.clone(),
            input_wire_values: bundle.input_wire_values.clone(),
            garbler_input: bundle.garbler_input.clone(),
        }
    }

    /// Encode to a compact binary blob.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut out = Vec::new();
        out.extend_from_slice(SIDECAR_MAGIC);
        out.push(SIDECAR_FORMAT_V1);
        out.extend_from_slice(&self.k.to_le_bytes());
        out.push(u8::from(self.proof_should_verify));
        write_ark(&mut out, &self.vk)?;
        write_ark(&mut out, &self.proof)?;
        out.extend_from_slice(&(self.public.len() as u32).to_le_bytes());
        for fr in &self.public {
            write_ark(&mut out, fr)?;
        }
        out.extend_from_slice(&(self.input_wire_values.len() as u32).to_le_bytes());
        for w in &self.input_wire_values {
            out.extend_from_slice(&w.label0.to_bytes());
            out.extend_from_slice(&w.label1.to_bytes());
        }
        // GarblerInput: public_params_len + vk (vk already stored; keep len for rebuild)
        out.extend_from_slice(&(self.garbler_input.public_params_len as u32).to_le_bytes());
        // vk duplicated for self-contained garbler_input rebuild
        write_ark(&mut out, &self.garbler_input.vk)?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let mut c = Cursor::new(bytes);
        if c.read_exact(4)? != SIDECAR_MAGIC {
            return Err(StoreError::BadMeta("sidecar bad magic"));
        }
        if c.read_u8()? != SIDECAR_FORMAT_V1 {
            return Err(StoreError::BadMeta("sidecar bad format"));
        }
        let k = c.read_u32()?;
        let proof_should_verify = c.read_u8()? != 0;
        let vk: ark::VerifyingKey<ark::Bn254> = read_ark(&mut c)?;
        let proof: ark::Proof<ark::Bn254> = read_ark(&mut c)?;
        let n_pub = c.read_u32()? as usize;
        let mut public = Vec::with_capacity(n_pub);
        for _ in 0..n_pub {
            public.push(read_ark(&mut c)?);
        }
        let n_wires = c.read_u32()? as usize;
        let mut input_wire_values = Vec::with_capacity(n_wires);
        for _ in 0..n_wires {
            let l0 = c.read_array16()?;
            let l1 = c.read_array16()?;
            input_wire_values.push(GarbledWire {
                label0: S::from_bytes(l0),
                label1: S::from_bytes(l1),
            });
        }
        let public_params_len = c.read_u32()? as usize;
        let gi_vk: ark::VerifyingKey<ark::Bn254> = read_ark(&mut c)?;
        if !c.is_empty() {
            return Err(StoreError::BadMeta("sidecar trailing bytes"));
        }
        Ok(Self {
            k,
            proof_should_verify,
            vk,
            proof,
            public,
            input_wire_values,
            garbler_input: GarblerInput {
                public_params_len,
                vk: gi_vk,
            },
        })
    }
}

/// Persist sidecar next to the CT stream and update meta hashes.
pub fn write_sidecar(
    store: &CiphertextStore,
    instance_id: u32,
    sidecar: &Groth16EvalSidecar,
    meta: &mut crate::phase_c::ciphertext_store::CiphertextMeta,
) -> Result<(), StoreError> {
    let bytes = sidecar.encode()?;
    let (hash, file) = store.write_sidecar_bytes(instance_id, &bytes)?;
    meta.sidecar_file = Some(file);
    meta.sidecar_hash = Some(hash);
    store.write_meta(meta)?;
    Ok(())
}

/// Load and verify sidecar for an instance.
pub fn load_sidecar(
    store: &CiphertextStore,
    instance_id: u32,
) -> Result<Groth16EvalSidecar, StoreError> {
    let meta = store.load_meta(instance_id)?;
    let bytes = store.open_sidecar_verified(&meta)?;
    Groth16EvalSidecar::decode(&bytes)
}

/// Rebuild a [`Groth16AssertBundle`] from store meta + sidecar (no CT load).
pub fn bundle_from_store(
    store: &CiphertextStore,
    instance_id: u32,
) -> Result<Groth16AssertBundle, StoreError> {
    let meta = store.verify(instance_id)?;
    let side = load_sidecar(store, instance_id)?;
    Ok(Groth16AssertBundle {
        seed: meta.seed,
        k: side.k,
        l_invalid: meta.l_invalid,
        l_valid: meta.l_valid,
        ciphertext_hash: meta.ciphertext_hash,
        true_wire: meta.true_wire,
        false_wire: meta.false_wire,
        proof_should_verify: side.proof_should_verify,
        vk: side.vk,
        proof: side.proof,
        public: side.public,
        input_wire_values: side.input_wire_values,
        garbler_input: side.garbler_input,
    })
}

fn write_ark<T: CanonicalSerialize>(out: &mut Vec<u8>, t: &T) -> Result<(), StoreError> {
    let mut buf = Vec::new();
    t.serialize_compressed(&mut buf)
        .map_err(|_| StoreError::BadMeta("ark serialize"))?;
    out.extend_from_slice(&(buf.len() as u32).to_le_bytes());
    out.extend_from_slice(&buf);
    Ok(())
}

fn read_ark<T: CanonicalDeserialize>(c: &mut Cursor<'_>) -> Result<T, StoreError> {
    let len = c.read_u32()? as usize;
    let bytes = c.read_exact(len)?;
    T::deserialize_compressed(&mut &bytes[..]).map_err(|_| StoreError::BadMeta("ark deserialize"))
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn read_exact(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        if self.pos + n > self.buf.len() {
            return Err(StoreError::BadMeta("sidecar truncated"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn read_u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.read_exact(1)?[0])
    }
    fn read_u32(&mut self) -> Result<u32, StoreError> {
        let b = self.read_exact(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn read_array16(&mut self) -> Result<[u8; 16], StoreError> {
        let b = self.read_exact(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phase_c::ciphertext_store::CiphertextStore;
    use garbled_snark_verifier::ark::{self, CircuitSpecificSetupSNARK, SNARK, UniformRand};
    use garbled_snark_verifier::test_utils::DummyCircuit;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn sidecar_roundtrip_ark_only() {
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
        let side = Groth16EvalSidecar {
            k: 4,
            proof_should_verify: true,
            vk: vk.clone(),
            proof,
            public,
            input_wire_values: vec![],
            garbler_input: GarblerInput {
                public_params_len: 1,
                vk,
            },
        };
        let enc = side.encode().unwrap();
        let dec = Groth16EvalSidecar::decode(&enc).unwrap();
        assert_eq!(dec.k, 4);
        assert!(dec.proof_should_verify);
        assert_eq!(dec.public.len(), 1);
        assert_eq!(dec.garbler_input.public_params_len, 1);

        let dir = std::env::temp_dir().join(format!("beacon-sidecar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = CiphertextStore::open(&dir).unwrap();
        let mut meta = store
            .persist_bytes_sha256(0, b"ct", 1, 1, 0, [1; 32], [2; 32])
            .unwrap();
        write_sidecar(&store, 0, &side, &mut meta).unwrap();
        assert!(meta.sidecar_hash.is_some());
        let loaded = load_sidecar(&store, 0).unwrap();
        assert_eq!(loaded.k, 4);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
