//! Claim Mini – the first concrete verification circuit for Cube BitVM3-style.
//!
//! Statement:
//!   H_new == SHA256( H_old || t1 || t2 || t3 || t4 )
//!   AND
//!   total_out <= total_in

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

/// All public inputs of Claim Mini (176 bytes total).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimMini {
    pub h_old: [u8; 32],
    pub h_new: [u8; 32],
    pub total_in: u64,
    pub total_out: u64,
    pub t1: [u8; 32],
    pub t2: [u8; 32],
    pub t3: [u8; 32],
    pub t4: [u8; 32],
}

impl ClaimMini {
    /// Serialize the claim into the exact preimage that is hashed.
    pub fn preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(&self.h_old);
        buf.extend_from_slice(&self.t1);
        buf.extend_from_slice(&self.t2);
        buf.extend_from_slice(&self.t3);
        buf.extend_from_slice(&self.t4);
        buf
    }

    /// Recompute the state root.
    pub fn compute_root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.preimage());
        hasher.finalize().into()
    }

    /// The core verification function (this is what the circuit computes).
    /// Returns `true` if and only if the claim is valid.
    pub fn verify(&self) -> bool {
        let balance_ok = self.total_out <= self.total_in;
        let root_ok = self.compute_root() == self.h_new;
        balance_ok && root_ok
    }

    /// Helper for tests / demos: create a valid claim from a previous root and transfers.
    pub fn make_valid(
        h_old: [u8; 32],
        total_in: u64,
        total_out: u64,
        t1: [u8; 32],
        t2: [u8; 32],
        t3: [u8; 32],
        t4: [u8; 32],
    ) -> Self {
        let mut claim = ClaimMini {
            h_old,
            h_new: [0u8; 32], // placeholder
            total_in,
            total_out,
            t1,
            t2,
            t3,
            t4,
        };
        claim.h_new = claim.compute_root();
        claim
    }
}

/// Simple simulation of the final output wire.
/// In a real garbled circuit this would be a pair of labels (True-label, False-label).
/// Here we just model the Boolean result and the idea of L*.
#[derive(Clone, Debug)]
pub struct OutputWire {
    pub value: bool,
    /// In a real implementation this would be the 32-byte label corresponding to `false`.
    /// We keep a placeholder so the rest of the code can already talk about L*.
    pub false_label_placeholder: [u8; 32],
}

impl OutputWire {
    pub fn from_claim(claim: &ClaimMini) -> Self {
        let value = claim.verify();
        // In a real garbling this label is chosen randomly at setup.
        // For the simulation we just hash something deterministic so tests are reproducible.
        let mut hasher = Sha256::new();
        hasher.update(b"L*_simulation");
        hasher.update(claim.preimage());
        let false_label_placeholder = hasher.finalize().into();

        OutputWire {
            value,
            false_label_placeholder,
        }
    }

    /// Returns Some(L*) if and only if the claim is invalid.
    pub fn fraud_secret(&self) -> Option<[u8; 32]> {
        if !self.value {
            Some(self.false_label_placeholder)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy32(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = seed;
        a
    }

    #[test]
    fn valid_claim_passes() {
        let claim = ClaimMini::make_valid(
            dummy32(1),
            100_000,
            50_000,
            dummy32(10),
            dummy32(11),
            dummy32(12),
            dummy32(13),
        );
        assert!(claim.verify());
        let wire = OutputWire::from_claim(&claim);
        assert!(wire.value);
        assert!(wire.fraud_secret().is_none());
    }

    #[test]
    fn inflation_is_rejected() {
        let mut claim = ClaimMini::make_valid(
            dummy32(1),
            100_000,
            50_000,
            dummy32(10),
            dummy32(11),
            dummy32(12),
            dummy32(13),
        );
        // Engine tries to claim more out than in
        claim.total_out = 200_000;
        assert!(!claim.verify());
        let wire = OutputWire::from_claim(&claim);
        assert!(!wire.value);
        assert!(wire.fraud_secret().is_some());
    }

    #[test]
    fn wrong_root_is_rejected() {
        let mut claim = ClaimMini::make_valid(
            dummy32(1),
            100_000,
            50_000,
            dummy32(10),
            dummy32(11),
            dummy32(12),
            dummy32(13),
        );
        // Engine lies about the new root
        claim.h_new = dummy32(0xFF);
        assert!(!claim.verify());
        let wire = OutputWire::from_claim(&claim);
        assert!(wire.fraud_secret().is_some());
    }
}
