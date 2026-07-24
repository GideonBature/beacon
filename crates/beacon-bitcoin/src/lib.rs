//! Bitcoin-shaped [`DisputeBackend`](beacon_core::DisputeBackend) skeleton.
//!
//! # What this is
//!
//! A lifecycle-compatible backend that records a **simulated** Bitcoin
//! transaction journal aligned with RFC-0006. Each entry carries a
//! [`TxTemplate`] / [`ScriptIntent`] describing the spending policy a real
//! backend must eventually realize (commit, challenge, hashlock disprove,
//! timeout withdraw, punish).
//!
//! | Protocol step | Journal entry |
//! |---------------|---------------|
//! | `assert` | [`TxKind::Assert`] + [`ScriptIntent::AssertCommit`] |
//! | `challenge` | [`TxKind::Challenge`] + [`ScriptIntent::ChallengeOpen`] |
//! | invalid evidence | [`TxKind::Disprove`] + [`ScriptIntent::DisproveHashlock`] |
//! | `finalize` → Accepted | [`TxKind::Withdraw`] + [`ScriptIntent::WithdrawTimeout`] |
//! | `finalize` → Rejected | [`TxKind::Punish`] + [`ScriptIntent::PunishBond`] |
//!
//! # What this is not
//!
//! - No broadcasting, wallets, Taproot key setup, or networking
//! - No `BitVM3` garbled circuits
//! - Verification still uses [`Verifiable::check`](beacon_core::Verifiable::check)
//!   via the embedded [`MockBackend`](beacon_mock::MockBackend)
//!
//! Assert / Withdraw templates **do** compile to offline `bitcoin` crate Script /
//! Transaction skeletons via [`compile`] / [`compile_journal`]. Challenge /
//! Disprove / Punish remain template-only for now.

#![forbid(unsafe_code)]

mod compile;
mod template;
mod tx;

use beacon_core::{
    AssertionId, BackendId, ChallengerId, Deadline, DisputeBackend, Instant, Result, Settlement,
    Verifiable,
};
use beacon_events::{ChallengeResult, Event, RecordingSink};
use beacon_mock::{AssertionView, MockBackend, MockConfig};

pub use compile::{compile, compile_journal, CompileError, CompiledTx, ASSERT_COMMIT_TAG};
pub use template::{ScriptIntent, TxTemplate};
pub use tx::{SimulatedTx, TxKind, Txid};

/// Bitcoin-shaped backend: mock lifecycle + templated transaction journal.
pub struct BitcoinBackend<E, S = RecordingSink> {
    mock: MockBackend<E, S>,
    journal: Vec<SimulatedTx>,
    next_index: u64,
    /// Placeholder bond amount attached to templates (sats).
    bond_sats: u64,
}

impl<E: std::fmt::Debug, S: std::fmt::Debug> std::fmt::Debug for BitcoinBackend<E, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitcoinBackend")
            .field("mock", &self.mock)
            .field("journal", &self.journal)
            .field("next_index", &self.next_index)
            .field("bond_sats", &self.bond_sats)
            .finish()
    }
}

impl<E> Default for BitcoinBackend<E, RecordingSink> {
    fn default() -> Self {
        Self::new(MockConfig::default())
    }
}

impl<E> BitcoinBackend<E, RecordingSink> {
    /// Create a backend with a recording event sink and default bond (`0`).
    #[must_use]
    pub fn new(config: MockConfig) -> Self {
        Self::with_bond(config, 0)
    }

    /// Create a backend that stamps `bond_sats` onto each template.
    #[must_use]
    pub fn with_bond(config: MockConfig, bond_sats: u64) -> Self {
        Self {
            mock: MockBackend::new(config),
            journal: Vec::new(),
            next_index: 0,
            bond_sats,
        }
    }

    /// Borrow recorded lifecycle events.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        self.mock.events()
    }
}

impl<E, S> BitcoinBackend<E, S> {
    /// Backend id used for this implementation.
    #[must_use]
    pub fn backend_id() -> BackendId {
        BackendId::new("bitcoin-sim")
    }

    /// Current logical time (delegated to the mock clock).
    #[must_use]
    pub fn now(&self) -> Instant {
        self.mock.now()
    }

    /// Set logical time.
    pub fn set_now(&mut self, now: Instant) {
        self.mock.set_now(now);
    }

    /// Advance logical time.
    pub fn advance(&mut self, delta: u64) {
        self.mock.advance(delta);
    }

    /// Borrow the simulated transaction journal in order.
    #[must_use]
    pub fn journal(&self) -> &[SimulatedTx] {
        &self.journal
    }

    /// Last journal txid for `assertion_id`, if any.
    #[must_use]
    pub fn tip_txid(&self, assertion_id: AssertionId) -> Option<Txid> {
        self.journal
            .iter()
            .rev()
            .find(|tx| tx.assertion_id == assertion_id)
            .map(|tx| tx.txid)
    }

    fn push_template(&mut self, locktime: Option<Instant>, template: TxTemplate) -> Txid {
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        let tx = SimulatedTx::from_template(index, locktime, template);
        let txid = tx.txid;
        self.journal.push(tx);
        txid
    }
}

impl<E: Verifiable, S> BitcoinBackend<E, S> {
    /// Inspect assertion state (delegates to mock storage).
    #[must_use]
    pub fn get(&self, id: AssertionId) -> Option<AssertionView> {
        self.mock.get(id)
    }
}

impl<E: Verifiable, S: beacon_events::EventSink> DisputeBackend for BitcoinBackend<E, S> {
    type Evidence = E;

    fn assert(&mut self, evidence: Self::Evidence, deadline: Deadline) -> Result<AssertionId> {
        let id = self.mock.assert(evidence, deadline)?;
        let bond = self.bond_sats;
        self.push_template(
            Some(deadline.instant()),
            TxTemplate::new(
                id,
                ScriptIntent::AssertCommit {
                    challenge_deadline: deadline.instant(),
                },
                None,
                bond,
            ),
        );
        Ok(id)
    }

    fn challenge(&mut self, assertion: AssertionId, challenger: ChallengerId) -> Result<()> {
        self.mock.challenge(assertion, challenger.clone())?;
        let view = self
            .mock
            .get(assertion)
            .ok_or(beacon_core::Error::NotFound)?;
        let deadline = view.deadline.instant();
        let prev = self.tip_txid(assertion);
        let bond = self.bond_sats;
        self.push_template(
            Some(deadline),
            TxTemplate::new(
                assertion,
                ScriptIntent::ChallengeOpen {
                    challenger: challenger.clone(),
                    challenge_deadline: deadline,
                },
                prev,
                bond,
            ),
        );
        if view.challenge_result == Some(ChallengeResult::Disproven) {
            let prev = self.tip_txid(assertion);
            self.push_template(
                None,
                TxTemplate::new(
                    assertion,
                    ScriptIntent::DisproveHashlock {
                        challenger: challenger.clone(),
                    },
                    prev,
                    bond,
                ),
            );
        }
        Ok(())
    }

    fn finalize(&mut self, assertion: AssertionId) -> Result<Settlement> {
        let view = self
            .mock
            .get(assertion)
            .ok_or(beacon_core::Error::NotFound)?;
        let unlocked_at = view.deadline.instant();
        let challenger = self
            .journal
            .iter()
            .rev()
            .find_map(|tx| match &tx.template.intent {
                ScriptIntent::ChallengeOpen { challenger, .. }
                | ScriptIntent::DisproveHashlock { challenger }
                | ScriptIntent::PunishBond { challenger } => Some(challenger.clone()),
                _ => None,
            });
        let settlement = self.mock.finalize(assertion)?;
        let prev = self.tip_txid(assertion);
        let bond = self.bond_sats;
        match settlement.outcome {
            beacon_core::Outcome::Accepted => {
                self.push_template(
                    None,
                    TxTemplate::new(
                        assertion,
                        ScriptIntent::WithdrawTimeout { unlocked_at },
                        prev,
                        bond,
                    ),
                );
            }
            beacon_core::Outcome::Rejected => {
                let challenger = challenger.unwrap_or_else(|| ChallengerId::new("unknown"));
                self.push_template(
                    None,
                    TxTemplate::new(
                        assertion,
                        ScriptIntent::PunishBond { challenger },
                        prev,
                        bond,
                    ),
                );
            }
        }
        Ok(settlement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_core::{AssertionState, Engine, Error, Outcome};
    use beacon_mock::MockEvidence;

    fn engine() -> Engine<BitcoinBackend<MockEvidence>> {
        Engine::new(BitcoinBackend::default())
    }

    #[test]
    fn lifecycle_accept_records_assert_and_withdraw_templates() {
        let mut engine = engine();
        let id = engine
            .assert(MockEvidence::valid("root"), Deadline::from_raw(10))
            .unwrap();

        let journal = engine.backend().journal();
        assert_eq!(journal[0].kind, TxKind::Assert);
        assert!(matches!(
            journal[0].template.intent,
            ScriptIntent::AssertCommit {
                challenge_deadline
            } if challenge_deadline == Instant::new(10)
        ));

        engine.backend_mut().set_now(Instant::new(10));
        let settlement = engine.finalize(id).unwrap();
        assert!(settlement.is_accepted());

        let journal = engine.backend().journal();
        assert_eq!(journal[1].kind, TxKind::Withdraw);
        assert!(matches!(
            journal[1].template.intent,
            ScriptIntent::WithdrawTimeout { unlocked_at } if unlocked_at == Instant::new(10)
        ));
        assert_eq!(journal[1].template.spends, Some(journal[0].txid));
        assert_eq!(
            engine.backend().get(id).unwrap().state,
            AssertionState::Accepted
        );
    }

    #[test]
    fn lifecycle_reject_records_script_intents() {
        let mut engine = engine();
        let id = engine
            .assert(MockEvidence::invalid("bad"), Deadline::from_raw(100))
            .unwrap();
        engine.challenge(id, ChallengerId::new("watcher")).unwrap();
        let settlement = engine.finalize(id).unwrap();
        assert_eq!(settlement.outcome, Outcome::Rejected);

        let intents: Vec<_> = engine
            .backend()
            .journal()
            .iter()
            .map(|t| t.template.intent.tx_kind())
            .collect();
        assert_eq!(
            intents,
            vec![
                TxKind::Assert,
                TxKind::Challenge,
                TxKind::Disprove,
                TxKind::Punish,
            ]
        );
        assert!(matches!(
            engine.backend().journal()[2].template.intent,
            ScriptIntent::DisproveHashlock { ref challenger }
                if challenger.as_str() == "watcher"
        ));
        assert!(matches!(
            engine.backend().journal()[3].template.intent,
            ScriptIntent::PunishBond { ref challenger }
                if challenger.as_str() == "watcher"
        ));
    }

    #[test]
    fn upheld_challenge_has_no_disprove_tx() {
        let mut engine = engine();
        let id = engine
            .assert(MockEvidence::valid("ok"), Deadline::from_raw(50))
            .unwrap();
        engine.challenge(id, ChallengerId::new("c")).unwrap();
        let settlement = engine.finalize(id).unwrap();
        assert!(settlement.is_accepted());

        let kinds: Vec<_> = engine.backend().journal().iter().map(|t| t.kind).collect();
        assert_eq!(
            kinds,
            vec![TxKind::Assert, TxKind::Challenge, TxKind::Withdraw]
        );
        assert!(!kinds.contains(&TxKind::Disprove));
    }

    #[test]
    fn rejects_ops_after_settlement() {
        let mut engine = engine();
        let id = engine
            .assert(MockEvidence::valid("root"), Deadline::from_raw(1))
            .unwrap();
        engine.backend_mut().set_now(Instant::new(1));
        let _ = engine.finalize(id).unwrap();
        assert_eq!(
            engine.challenge(id, ChallengerId::new("late")),
            Err(Error::AlreadySettled)
        );
        assert_eq!(engine.finalize(id), Err(Error::AlreadySettled));
    }

    #[test]
    fn bond_sats_stamp_on_templates() {
        let mut engine = Engine::new(BitcoinBackend::with_bond(MockConfig::default(), 50_000));
        let id = engine
            .assert(MockEvidence::valid("x"), Deadline::from_raw(2))
            .unwrap();
        assert_eq!(engine.backend().journal()[0].template.value_sats, 50_000);
        assert_eq!(id, engine.backend().journal()[0].assertion_id);
    }
}
