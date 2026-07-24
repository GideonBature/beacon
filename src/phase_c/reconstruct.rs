//! Wide-label / share reconstruction for Phase C.
//!
//! - `gsv-vsss`: Shamir reconstruct via upstream `lagrange_interpolate_whole_polynomial`
//! - otherwise: adaptor label material is the reconstructed seed (Phase B stand-in)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Compact share bundle published at cut-and-choose setup (check set).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareBundle {
    pub n: u32,
    pub threshold: u32,
    /// Check-set shares: `(index, 32-byte field element)`.
    pub check_shares: Vec<(u32, [u8; 32])>,
    /// Index opened via adaptor on Assert.
    pub adaptor_index: u32,
}

impl ShareBundle {
    /// Minimal synthetic bundle for demos (no upstream VSSS required).
    pub fn synthetic_from_adaptor_secret(adaptor_secret: &[u8; 32]) -> Self {
        let mut s0 = [0u8; 32];
        let mut s1 = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"Beacon/PhaseC/Share0");
        hasher.update(adaptor_secret);
        s0.copy_from_slice(&hasher.finalize());

        let mut hasher = Sha256::new();
        hasher.update(b"Beacon/PhaseC/Share1");
        hasher.update(adaptor_secret);
        s1.copy_from_slice(&hasher.finalize());

        Self {
            n: 3,
            threshold: 2,
            check_shares: vec![(0, s0), (1, s1)],
            adaptor_index: 2,
        }
    }
}

/// Reconstruct the evaluation seed / wide-label material.
///
/// `adaptor_share` is the 32-byte secret recovered from the Phase B opening
/// (stand-in for a VSSS Fr share). For GSV Fr shares use
/// [`adaptor_share_from_gsv_fr_be`] first when feeding the lagrange path.
#[must_use]
pub fn reconstruct_label_seed(
    bundle: Option<&ShareBundle>,
    adaptor_share: &[u8; 32],
) -> [u8; 32] {
    match bundle {
        None => *adaptor_share,
        Some(b) => linked::reconstruct(b, adaptor_share),
    }
}

/// Convert a GSV adaptor Fr share (**big-endian**) to the little-endian
/// 32-byte form expected by [`ShareBundle`] / `gsv-vsss` lagrange reconstruct.
#[cfg(feature = "gsv-vsss")]
#[must_use]
pub fn adaptor_share_from_gsv_fr_be(fr_be: &[u8; 32]) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    use ark_secp256k1::Fr;
    let fr = Fr::from_be_bytes_mod_order(fr_be);
    let mut out = [0u8; 32];
    let bytes = fr.into_bigint().to_bytes_le();
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

#[cfg(feature = "gsv-vsss")]
mod linked {
    use super::*;
    use ark_ff::{BigInteger, PrimeField};
    use ark_secp256k1::Fr;
    use garbled_snark_verifier::cut_and_choose::vsss::lagrange_interpolate_whole_polynomial;

    fn fr_from_bytes(bytes: &[u8; 32]) -> Fr {
        Fr::from_le_bytes_mod_order(bytes)
    }

    fn fr_to_bytes(fr: &Fr) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = fr.into_bigint().to_bytes_le();
        let n = bytes.len().min(32);
        out[..n].copy_from_slice(&bytes[..n]);
        out
    }

    pub fn reconstruct(bundle: &ShareBundle, adaptor_share: &[u8; 32]) -> [u8; 32] {
        let mut known: Vec<(usize, Fr)> = bundle
            .check_shares
            .iter()
            .map(|(i, b)| (*i as usize, fr_from_bytes(b)))
            .collect();
        known.push((bundle.adaptor_index as usize, fr_from_bytes(adaptor_share)));

        let missing: Vec<usize> = (0..bundle.n as usize)
            .filter(|i| known.iter().all(|(j, _)| j != i))
            .collect();

        let mut hasher = Sha256::new();
        hasher.update(b"Beacon/PhaseC/VsssSeed/v1");
        for (i, fr) in &known {
            hasher.update((*i as u32).to_le_bytes());
            hasher.update(fr_to_bytes(fr));
        }

        if known.len() >= bundle.threshold as usize && !missing.is_empty() {
            let missing_shares =
                lagrange_interpolate_whole_polynomial(&known, &missing);
            for (i, fr) in missing.iter().zip(missing_shares.iter()) {
                hasher.update((*i as u32).to_le_bytes());
                hasher.update(fr_to_bytes(fr));
            }
        }

        hasher.finalize().into()
    }
}

#[cfg(not(feature = "gsv-vsss"))]
mod linked {
    use super::*;

    pub fn reconstruct(bundle: &ShareBundle, adaptor_share: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"Beacon/PhaseC/VsssSeedStandIn/v1");
        hasher.update(bundle.n.to_le_bytes());
        hasher.update(bundle.threshold.to_le_bytes());
        hasher.update(bundle.adaptor_index.to_le_bytes());
        for (i, s) in &bundle.check_shares {
            hasher.update(i.to_le_bytes());
            hasher.update(s);
        }
        hasher.update(adaptor_share);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_bundle_reconstructs() {
        let secret = [9u8; 32];
        let bundle = ShareBundle::synthetic_from_adaptor_secret(&secret);
        let a = reconstruct_label_seed(Some(&bundle), &secret);
        let b = reconstruct_label_seed(Some(&bundle), &secret);
        assert_eq!(a, b);
        assert_ne!(a, secret); // folded, not raw adaptor secret
    }
}
