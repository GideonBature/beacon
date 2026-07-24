//! Structured transaction templates for the Bitcoin dispute graph (RFC-0006).
//!
//! Templates describe *what a future on-chain backend must realize*, not Bitcoin
//! Script or PSBTs yet. Filling these fields with real Taproot / CSV / hashlock
//! constructions is the next implementation layer after the simulated journal.

use beacon_core::{AssertionId, ChallengerId, Instant};

use crate::tx::{TxKind, Txid};

/// Intended spending / enforcement policy for a simulated transaction.
///
/// Real backends map these intents onto Taproot leaves, CSV/CLTV, and hashlocks.
/// `BitVM3`-style garbling would attach to [`ScriptIntent::DisproveHashlock`]
/// later — it is intentionally not required here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ScriptIntent {
    /// Commit an assertion; funds/time-locked until challenge window ends or dispute.
    AssertCommit {
        /// Absolute challenge-window deadline (logical time / future block height).
        challenge_deadline: Instant,
    },
    /// Open a challenge against a prior assert output.
    ChallengeOpen {
        /// Challenger identity (stand-in for a spending key / bond).
        challenger: ChallengerId,
        /// Window still relevant for race conditions.
        challenge_deadline: Instant,
    },
    /// Reveal fraud / invalid-evidence witness (future: hashlock or garble secret).
    DisproveHashlock {
        /// Challenger that produced the disproof.
        challenger: ChallengerId,
    },
    /// Timeout path: assertion upheld, operator withdraws after locktime.
    WithdrawTimeout {
        /// Deadline that has been reached.
        unlocked_at: Instant,
    },
    /// Slash / punish path after successful disprove.
    PunishBond {
        /// Challenger credited by the punishment (informational in sim).
        challenger: ChallengerId,
    },
}

impl ScriptIntent {
    /// Protocol [`TxKind`] this intent belongs to.
    #[must_use]
    pub const fn tx_kind(&self) -> TxKind {
        match self {
            Self::AssertCommit { .. } => TxKind::Assert,
            Self::ChallengeOpen { .. } => TxKind::Challenge,
            Self::DisproveHashlock { .. } => TxKind::Disprove,
            Self::WithdrawTimeout { .. } => TxKind::Withdraw,
            Self::PunishBond { .. } => TxKind::Punish,
        }
    }
}

/// Template payload attached to each journal entry.
///
/// A production backend would compile this into a PSBT / transaction. The sim
/// backend only records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxTemplate {
    /// Assertion this template enforces.
    pub assertion_id: AssertionId,
    /// Script / covenant intent.
    pub intent: ScriptIntent,
    /// Outpoint this template spends, when extending a prior tip.
    pub spends: Option<Txid>,
    /// Value placeholder (sats). `0` in the sim until bonds are modeled.
    pub value_sats: u64,
}

impl TxTemplate {
    /// Build a template.
    #[must_use]
    pub const fn new(
        assertion_id: AssertionId,
        intent: ScriptIntent,
        spends: Option<Txid>,
        value_sats: u64,
    ) -> Self {
        Self {
            assertion_id,
            intent,
            spends,
            value_sats,
        }
    }
}
