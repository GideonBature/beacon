//! Map GSV 16-byte wire labels onto 32-byte Taproot hashlock preimages.

use sha2::{Digest, Sha256};

/// Expand a garbling label (or any short secret) to a 32-byte `L*`.
#[must_use]
pub fn expand_label_bytes(label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"Beacon/PhaseC/L*/v1");
    hasher.update(label);
    hasher.finalize().into()
}

/// Deterministic garble seed from opening label material.
#[must_use]
pub fn seed_from_label_material(material: &[u8; 32]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"Beacon/PhaseC/GarbleSeed/v1");
    hasher.update(material);
    let dig: [u8; 32] = hasher.finalize().into();
    u64::from_le_bytes(dig[0..8].try_into().expect("8 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_is_stable() {
        assert_eq!(expand_label_bytes(b"abc"), expand_label_bytes(b"abc"));
        assert_ne!(expand_label_bytes(b"a"), expand_label_bytes(b"b"));
    }
}
