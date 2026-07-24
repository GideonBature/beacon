//! Phase B extractable opening – Schnorr adaptor offset.

use rand::{CryptoRng, RngCore};
use secp256k1::{Keypair, Message, SecretKey, Secp256k1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::phase_b::adaptor::{
    complete_and_extract, create_adapted_signature, AdaptedSignature, AdaptorError,
};

/// Assert-witness opening that reveals label material via adaptor extraction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptorOpening {
    /// Protocol version (`VERSION_PHASE_B`).
    pub version: u8,
    /// Evaluation instance id (VSSS compatibility).
    pub instance_id: u32,
    /// Engine x-only pubkey that produced the completed BIP340 signature.
    pub signer_xonly: [u8; 32],
    /// Adaptor point `T = t·G` (x-only).
    pub adaptor_point: [u8; 32],
    /// BIP340 nonce `R.x`.
    pub nonce_x: [u8; 32],
    /// Adapted scalar `s' = s − t`.
    pub adapted_s: [u8; 32],
    /// Completed BIP340 scalar `s` (revealed in Assert).
    pub completed_s: [u8; 32],
    /// 32-byte message the signature covers.
    pub message: [u8; 32],
    /// Hash of the public claim bytes.
    pub public_inputs_hash: [u8; 32],
}

impl AdaptorOpening {
    pub const VERSION_PHASE_B: u8 = 2;

    /// Domain-separated message bound to the claim hash.
    pub fn claim_message(public_inputs_hash: &[u8; 32]) -> Message {
        let mut hasher = Sha256::new();
        hasher.update(b"Beacon/PhaseB/Assert/v1");
        hasher.update(public_inputs_hash);
        Message::from_digest(hasher.finalize().into())
    }

    /// Build an adaptor opening for `claim_bytes` under `signer`.
    pub fn create<R: RngCore + CryptoRng>(
        instance_id: u32,
        claim_bytes: &[u8],
        signer: &Keypair,
        rng: &mut R,
    ) -> Result<Self, AdaptorError> {
        let mut hasher = Sha256::new();
        hasher.update(claim_bytes);
        let public_inputs_hash: [u8; 32] = hasher.finalize().into();

        let adaptor_secret = SecretKey::new(rng);
        let message = Self::claim_message(&public_inputs_hash);
        let adapted = create_adapted_signature(signer, &message, &adaptor_secret)?;

        Ok(Self::from_adapted(instance_id, public_inputs_hash, adapted))
    }

    /// Convenience: fresh Engine keypair + opening (simulation / tests).
    pub fn create_ephemeral(
        instance_id: u32,
        claim_bytes: &[u8],
    ) -> Result<(Self, Keypair), AdaptorError> {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let signer = Keypair::new(&secp, &mut rng);
        let opening = Self::create(instance_id, claim_bytes, &signer, &mut rng)?;
        Ok((opening, signer))
    }

    fn from_adapted(
        instance_id: u32,
        public_inputs_hash: [u8; 32],
        adapted: AdaptedSignature,
    ) -> Self {
        Self {
            version: Self::VERSION_PHASE_B,
            instance_id,
            signer_xonly: adapted.signer_xonly,
            adaptor_point: adapted.adaptor_point,
            nonce_x: adapted.nonce_x,
            adapted_s: adapted.adapted_s,
            completed_s: adapted.completed_s,
            message: adapted.message,
            public_inputs_hash,
        }
    }

    fn as_adapted(&self) -> AdaptedSignature {
        AdaptedSignature {
            signer_xonly: self.signer_xonly,
            adaptor_point: self.adaptor_point,
            nonce_x: self.nonce_x,
            adapted_s: self.adapted_s,
            completed_s: self.completed_s,
            message: self.message,
        }
    }

    /// Recover adaptor secret `t` (verifies point + completed signature).
    pub fn extract_secret(&self) -> Result<SecretKey, AdaptorError> {
        complete_and_extract(&self.as_adapted())
    }

    /// Derive label material from the extracted adaptor secret.
    pub fn derive_label_material(&self) -> Result<[u8; 32], AdaptorError> {
        let t = self.extract_secret()?;
        let mut hasher = Sha256::new();
        hasher.update(b"CubePhaseBLabels");
        hasher.update(t.secret_bytes());
        Ok(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_extracts_deterministic_labels() {
        let claim = b"phase-b-claim";
        let (o1, _) = AdaptorOpening::create_ephemeral(0, claim).unwrap();
        let labels = o1.derive_label_material().unwrap();
        // Re-extract is stable.
        assert_eq!(labels, o1.derive_label_material().unwrap());
        assert_eq!(o1.version, AdaptorOpening::VERSION_PHASE_B);
    }

    #[test]
    fn tampered_completed_s_fails() {
        let (mut o, _) = AdaptorOpening::create_ephemeral(0, b"x").unwrap();
        o.completed_s[0] ^= 0xff;
        assert!(o.extract_secret().is_err());
    }
}
