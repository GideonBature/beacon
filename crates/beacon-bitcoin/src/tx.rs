//! Simulated transaction templates and identifiers (RFC-0006 mapping).
//!
//! These are **not** real Bitcoin transactions. They capture the fields a future
//! on-chain backend will need (kind, assertion binding, timelock, txid, script
//! intent) so the journal is structurally closer to a transaction graph.

use core::fmt;

use beacon_core::{AssertionId, Instant};
use sha2::{Digest, Sha256};

use crate::template::TxTemplate;

/// 32-byte simulated transaction id (double-SHA256 stand-in).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Txid([u8; 32]);

impl Txid {
    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Deterministic id from journal fields.
    #[must_use]
    pub fn derive(
        kind: TxKind,
        assertion_id: AssertionId,
        index: u64,
        locktime: Option<Instant>,
        prev: Option<Txid>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"beacon-bitcoin-sim-v1");
        hasher.update([kind as u8]);
        hasher.update(assertion_id.as_uuid().as_bytes());
        hasher.update(index.to_le_bytes());
        match locktime {
            Some(t) => {
                hasher.update([1]);
                hasher.update(t.get().to_le_bytes());
            }
            None => hasher.update([0]),
        }
        match prev {
            Some(p) => {
                hasher.update([1]);
                hasher.update(p.as_bytes());
            }
            None => hasher.update([0]),
        }
        let first = hasher.finalize();
        let second = Sha256::digest(first);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        Self(out)
    }
}

impl fmt::Display for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Txid({self})")
    }
}

/// Kind of simulated Bitcoin transaction (RFC-0006 mapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TxKind {
    /// Assertion / commit broadcast.
    Assert = 1,
    /// Challenge opened on-chain.
    Challenge = 2,
    /// Disprove / fraud path (challenger showed invalid evidence).
    Disprove = 3,
    /// Timeout / withdraw after accepted settlement.
    Withdraw = 4,
    /// Punishment finalization after rejected settlement.
    Punish = 5,
}

/// One simulated chain action tied to an assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulatedTx {
    /// Transaction role in the dispute graph.
    pub kind: TxKind,
    /// Assertion this action belongs to.
    pub assertion_id: AssertionId,
    /// Monotonic simulated tx index (broadcast order).
    pub index: u64,
    /// Simulated txid.
    pub txid: Txid,
    /// Absolute locktime / challenge deadline when applicable (logical time).
    pub locktime: Option<Instant>,
    /// Previous journal txid this action spends/extends, if any.
    pub prev_txid: Option<Txid>,
    /// Structured template a real backend would compile to Script/PSBT.
    pub template: TxTemplate,
}

impl SimulatedTx {
    /// Build a journal entry from a template and derive its txid.
    #[must_use]
    pub fn from_template(index: u64, locktime: Option<Instant>, template: TxTemplate) -> Self {
        let kind = template.intent.tx_kind();
        let assertion_id = template.assertion_id;
        let prev_txid = template.spends;
        let txid = Txid::derive(kind, assertion_id, index, locktime, prev_txid);
        Self {
            kind,
            assertion_id,
            index,
            txid,
            locktime,
            prev_txid,
            template,
        }
    }
}
