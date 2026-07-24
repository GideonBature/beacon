//! Bitcoin transaction templates for the Cube BitVM3-style dispute layer.
//!
//! These are logical descriptions of the three core transactions:
//!   - Assert
//!   - Disprove
//!   - Timeout / Withdraw
//!
//! They are intentionally kept as pure data + documentation so they can later
//! be turned into real `bitcoin` crate transactions on regtest / signet / mainnet.

use serde::{Deserialize, Serialize};

/// Relative timelock (in blocks) after which the Engine may spend the timeout path.
pub const DEFAULT_DISPUTE_WINDOW: u32 = 144; // ~1 day

/// Logical description of the Assert transaction.
///
/// The Engine posts this when it wants to claim that a particular ClaimMini is true.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssertTemplate {
    /// Any previous connector or funding outpoint (txid:vout).
    pub funding_outpoint: String,

    /// The claim being asserted (public statement).
    pub claim: crate::ClaimMini,

    /// Commitment to the false-output label: H(L*).
    /// In a real implementation this is a 32-byte SHA-256 hash.
    pub hash_of_false_label: [u8; 32],

    /// Relative timelock for the timeout path.
    pub dispute_window: u32,
}

impl AssertTemplate {
    /// Human-readable description of the locking script of the connector output.
    pub fn connector_script_description(&self) -> String {
        format!(
            "Taproot\n\
             ├── Leaf 0 (Disprove):  OP_SHA256 <{:?}> OP_EQUAL\n\
             └── Leaf 1 (Timeout):   <{}> OP_CSV  OP_DROP  <Engine_pubkey> OP_CHECKSIG",
            self.hash_of_false_label, self.dispute_window
        )
    }
}

/// Logical description of the Disprove transaction.
///
/// Anyone who obtains L* (by evaluating the circuit on an invalid claim)
/// can spend the Assert connector via the hashlock path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisproveTemplate {
    /// The Assert transaction id + vout of the connector.
    pub assert_outpoint: String,

    /// The false-output label L* obtained from circuit evaluation.
    pub false_label: [u8; 32],

    /// Where the slashed value goes (challenger, community pool, burn, …).
    pub slash_destination: String,
}

impl DisproveTemplate {
    pub fn script_description(&self) -> String {
        "Input: Assert connector (hashlock path)\n\
         Witness: <L*>\n\
         Effect: spends the connector, preventing Engine from ever taking the timeout path"
            .to_string()
    }
}

/// Logical description of the Timeout / Withdraw transaction.
///
/// After the relative timelock expires, and only if the connector was never
/// successfully Disproved, the Engine can claim the funds / finalize the state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeoutTemplate {
    /// The Assert connector outpoint (must still be unspent).
    pub assert_outpoint: String,

    /// The actual value being claimed (bridge reserve, user exit, …).
    pub reserve_outpoint: String,

    /// Engine’s public key (or MuSig key).
    pub engine_pubkey: String,
}

impl TimeoutTemplate {
    pub fn script_description(&self) -> String {
        format!(
            "Inputs:\n\
              0: Assert connector  →  must satisfy: <{}> OP_CSV + Engine signature\n\
              1: Reserve / Deposit →  pre-signed covenant / CheckCovenant\n\
             Output: Engine receives the funds",
            DEFAULT_DISPUTE_WINDOW
        )
    }
}

/// Convenience bundle that shows the whole happy / unhappy path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeFlow {
    pub assert: AssertTemplate,
    pub disprove: Option<DisproveTemplate>,
    pub timeout: Option<TimeoutTemplate>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClaimMini;

    fn dummy_claim() -> ClaimMini {
        ClaimMini::make_valid(
            [1u8; 32],
            100_000,
            40_000,
            [10u8; 32],
            [11u8; 32],
            [12u8; 32],
            [13u8; 32],
        )
    }

    #[test]
    fn assert_template_builds() {
        let claim = dummy_claim();
        let tmpl = AssertTemplate {
            funding_outpoint: "abc123:0".into(),
            claim,
            hash_of_false_label: [0x42; 32],
            dispute_window: DEFAULT_DISPUTE_WINDOW,
        };
        let desc = tmpl.connector_script_description();
        assert!(desc.contains("Disprove"));
        assert!(desc.contains("Timeout"));
    }
}
