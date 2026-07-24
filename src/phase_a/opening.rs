//! Phase A extractable opening – direct seed.
//!
//! The Engine reveals a 32-byte seed in the Assert witness.
//! From this seed anyone can deterministically derive the wide labels
//! (or, in this minimal version, simply re-derive the Claim Mini inputs
//! and evaluate the circuit).

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

/// The data that appears in the Assert witness for Phase A.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectSeedOpening {
    /// Protocol version so we can later switch to adaptor openings.
    pub version: u8,
    /// Which evaluation instance is being opened (for future VSSS compatibility).
    pub instance_id: u32,
    /// 32-byte seed.  In a real garbled-circuit setting this seed expands
    /// to the wide labels.  In Phase A it is enough to re-derive the claim.
    pub seed: [u8; 32],
    /// Hash of the public inputs / claim (for integrity).
    pub public_inputs_hash: [u8; 32],
}

impl DirectSeedOpening {
    pub const VERSION_PHASE_A: u8 = 1;

    /// Create an opening for a given claim.
    /// In Phase A we simply hash the claim serialization with a domain separator
    /// to obtain a deterministic seed.  Later this will be replaced by a real
    /// random seed that expands to garbled labels.
    pub fn from_claim_bytes(instance_id: u32, claim_bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"CubePhaseASeed");
        hasher.update(claim_bytes);
        let seed: [u8; 32] = hasher.finalize().into();

        let mut hasher2 = Sha256::new();
        hasher2.update(claim_bytes);
        let public_inputs_hash: [u8; 32] = hasher2.finalize().into();

        DirectSeedOpening {
            version: Self::VERSION_PHASE_A,
            instance_id,
            seed,
            public_inputs_hash,
        }
    }

    /// Derive a deterministic “label material” from the seed.
    /// In the real system this would expand into the wide labels of instance `a`.
    /// For Phase A we just return the seed itself as a stand-in.
    pub fn derive_label_material(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"CubePhaseALabels");
        hasher.update(&self.seed);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_is_deterministic() {
        let claim = b"dummy claim data";
        let o1 = DirectSeedOpening::from_claim_bytes(0, claim);
        let o2 = DirectSeedOpening::from_claim_bytes(0, claim);
        assert_eq!(o1.seed, o2.seed);
        assert_eq!(o1.public_inputs_hash, o2.public_inputs_hash);
    }
}
