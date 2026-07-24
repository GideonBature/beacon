//! Schnorr adaptor offset helpers (BIP340 signature + extractable secret).
//!
//! Construction (Phase B):
//! 1. Sample adaptor secret `t`, publish `T = t·G` (x-only).
//! 2. Produce a valid BIP340 signature `(R, s)` on the claim-binding message.
//! 3. Publish adapted scalar `s' = s − t` (known to the challenger before Assert
//!    in the full interactive protocol; included here for a self-contained demo).
//! 4. Anyone who sees `(s', s)` recovers `t = s − s'` and checks `T = t·G`.

use secp256k1::{
    Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey, SECP256K1,
};

/// Error from adaptor create / extract / verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdaptorError {
    BadSecret,
    BadPoint,
    ExtractMismatch,
    InvalidSignature,
}

impl std::fmt::Display for AdaptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSecret => write!(f, "invalid secret scalar"),
            Self::BadPoint => write!(f, "invalid public point"),
            Self::ExtractMismatch => write!(f, "extracted secret does not match adaptor point"),
            Self::InvalidSignature => write!(f, "completed BIP340 signature failed verification"),
        }
    }
}

impl std::error::Error for AdaptorError {}

/// Adapted signature material before / after Assert completion.
#[derive(Clone, Debug)]
pub struct AdaptedSignature {
    pub signer_xonly: [u8; 32],
    pub adaptor_point: [u8; 32],
    pub nonce_x: [u8; 32],
    pub adapted_s: [u8; 32],
    pub completed_s: [u8; 32],
    pub message: [u8; 32],
}

/// Create a BIP340 signature and adaptor offset for `message` under `signer`.
pub fn create_adapted_signature(
    signer: &Keypair,
    message: &Message,
    adaptor_secret: &SecretKey,
) -> Result<AdaptedSignature, AdaptorError> {
    let secp = Secp256k1::new();
    let (signer_xonly, _) = signer.x_only_public_key();
    let (adaptor_point, _) = PublicKey::from_secret_key(&secp, adaptor_secret).x_only_public_key();

    let sig = secp.sign_schnorr_no_aux_rand(message, signer);
    let sig_bytes = sig.as_ref();
    let mut nonce_x = [0u8; 32];
    let mut completed_s = [0u8; 32];
    nonce_x.copy_from_slice(&sig_bytes[..32]);
    completed_s.copy_from_slice(&sig_bytes[32..]);

    let s_sk = SecretKey::from_slice(&completed_s).map_err(|_| AdaptorError::BadSecret)?;
    let adapted = s_sk
        .add_tweak(&Scalar::from(adaptor_secret.negate()))
        .map_err(|_| AdaptorError::BadSecret)?;

    Ok(AdaptedSignature {
        signer_xonly: signer_xonly.serialize(),
        adaptor_point: adaptor_point.serialize(),
        nonce_x,
        adapted_s: adapted.secret_bytes(),
        completed_s,
        message: *message.as_ref(),
    })
}

/// Recover `t = s − s'` from adapted + completed scalars.
pub fn extract_adaptor_secret(
    adapted_s: &[u8; 32],
    completed_s: &[u8; 32],
) -> Result<SecretKey, AdaptorError> {
    let s = SecretKey::from_slice(completed_s).map_err(|_| AdaptorError::BadSecret)?;
    let sp = SecretKey::from_slice(adapted_s).map_err(|_| AdaptorError::BadSecret)?;
    s.add_tweak(&Scalar::from(sp.negate()))
        .map_err(|_| AdaptorError::BadSecret)
}

/// Extract `t` and check it matches the committed adaptor point `T`.
pub fn complete_and_extract(
    adapted: &AdaptedSignature,
) -> Result<SecretKey, AdaptorError> {
    let t = extract_adaptor_secret(&adapted.adapted_s, &adapted.completed_s)?;
    let (got, _) = PublicKey::from_secret_key(SECP256K1, &t).x_only_public_key();
    let expect =
        XOnlyPublicKey::from_slice(&adapted.adaptor_point).map_err(|_| AdaptorError::BadPoint)?;
    if got != expect {
        return Err(AdaptorError::ExtractMismatch);
    }

    // Completed signature must verify under the Engine key.
    let pk = XOnlyPublicKey::from_slice(&adapted.signer_xonly).map_err(|_| AdaptorError::BadPoint)?;
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&adapted.nonce_x);
    sig_bytes[32..].copy_from_slice(&adapted.completed_s);
    let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes)
        .map_err(|_| AdaptorError::InvalidSignature)?;
    let msg = Message::from_digest(adapted.message);
    SECP256K1
        .verify_schnorr(&sig, &msg, &pk)
        .map_err(|_| AdaptorError::InvalidSignature)?;

    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn extract_recovers_adaptor_secret() {
        let secp = Secp256k1::new();
        let signer = Keypair::new(&secp, &mut thread_rng());
        let t = SecretKey::new(&mut thread_rng());
        let msg = Message::from_digest([7u8; 32]);
        let adapted = create_adapted_signature(&signer, &msg, &t).unwrap();
        let recovered = complete_and_extract(&adapted).unwrap();
        assert_eq!(recovered.secret_bytes(), t.secret_bytes());
    }
}
