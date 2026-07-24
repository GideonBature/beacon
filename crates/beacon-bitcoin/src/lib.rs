//! Bitcoin-shaped [`DisputeBackend`](beacon_core::DisputeBackend) skeleton.
//!
//! # What this is
//!
//! A lifecycle-compatible backend that records a **simulated** Bitcoin
//! transaction journal aligned with RFC-0006:
//!
//! | Protocol step | Journal entry |
//! |---------------|---------------|
//! | `assert` | [`TxKind::Assert`] (locktime = challenge deadline) |
//! | `challenge` | [`TxKind::Challenge`] (+ [`TxKind::Disprove`] if evidence fails) |
//! | `finalize` → Accepted | [`TxKind::Withdraw`] |
//! | `finalize` → Rejected | [`TxKind::Punish`] |
//!
//! Each entry carries a deterministic [`Txid`], optional locktime, and a
//! `prev_txid` link so the journal forms a simple transaction graph.
//!
//! # What this is not
//!
//! - No real Bitcoin transactions, scripts, Taproot, or networking
//! - No `BitVM3` garbled circuits
//! - Verification still uses [`Verifiable::check`](beacon_core::Verifiable::check)
//!   via the embedded [`MockBackend`](beacon_mock::MockBackend)
//!
//! Real chain settlement replaces the journal + mock verify path later without
//! changing the [`DisputeBackend`](beacon_core::DisputeBackend) API.

#![forbid(unsafe_code)]

mod tx;

use beacon_core::{
    AssertionId, BackendId, ChallengerId, Deadline, DisputeBackend, Instant, Result, Settlement,
    Verifiable,
};
use beacon_events::{ChallengeResult, Event, RecordingSink};
use beacon_mock::{AssertionView, MockBackend, MockConfig};

pub use tx::{SimulatedTx, TxKind, Txid};

/// Bitcoin-shaped backend: mock lifecycle + transaction journal.
pub struct BitcoinBackend<E, S = RecordingSink> {
    mock: MockBackend<E, S>,
    journal: Vec<SimulatedTx>,
    next_index: u64,
}

impl<E: std::fmt::Debug, S: std::fmt::Debug> std::fmt::Debug for BitcoinBackend<E, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitcoinBackend")
            .field("mock", &self.mock)
            .field("journal", &self.journal)
            .field("next_index", &self.next_index)
            .finish()
    }
}

impl<E> Default for BitcoinBackend<E, RecordingSink> {
    fn default() -> Self {
        Self::new(MockConfig::default())
    }
}

impl<E> BitcoinBackend<E, RecordingSink> {
    /// Create a backend with a recording event sink.
    #[must_use]
    pub fn new(config: MockConfig) -> Self {
        Self {
            mock: MockBackend::new(config),
            journal: Vec::new(),
            next_index: 0,
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

    fn push_tx(
        &mut self,
        kind: TxKind,
        assertion_id: AssertionId,
        locktime: Option<Instant>,
    ) -> Txid {
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        let prev_txid = self.tip_txid(assertion_id);
        let tx = SimulatedTx::new(kind, assertion_id, index, locktime, prev_txid);
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
        self.push_tx(TxKind::Assert, id, Some(deadline.instant()));
        Ok(id)
    }

    fn challenge(&mut self, assertion: AssertionId, challenger: ChallengerId) -> Result<()> {
        self.mock.challenge(assertion, challenger)?;
        let locktime = self.mock.get(assertion).map(|v| v.deadline.instant());
        self.push_tx(TxKind::Challenge, assertion, locktime);
        if self.mock.get(assertion).and_then(|v| v.challenge_result)
            == Some(ChallengeResult::Disproven)
        {
            self.push_tx(TxKind::Disprove, assertion, None);
        }
        Ok(())
    }

    fn finalize(&mut self, assertion: AssertionId) -> Result<Settlement> {
        let settlement = self.mock.finalize(assertion)?;
        match settlement.outcome {
            beacon_core::Outcome::Accepted => {
                self.push_tx(TxKind::Withdraw, assertion, None);
            }
            beacon_core::Outcome::Rejected => {
                self.push_tx(TxKind::Punish, assertion, None);
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
    fn lifecycle_accept_records_assert_and_withdraw() {
        let mut engine = engine();
        let id = engine
            .assert(MockEvidence::valid("root"), Deadline::from_raw(10))
            .unwrap();

        let journal = engine.backend().journal();
        assert_eq!(journal.len(), 1);
        assert_eq!(journal[0].kind, TxKind::Assert);
        assert_eq!(journal[0].assertion_id, id);
        assert_eq!(journal[0].locktime, Some(Instant::new(10)));
        assert!(journal[0].prev_txid.is_none());

        assert_eq!(engine.finalize(id), Err(Error::DisputePending));
        engine.backend_mut().set_now(Instant::new(10));
        let settlement = engine.finalize(id).unwrap();
        assert!(settlement.is_accepted());

        let journal = engine.backend().journal();
        assert_eq!(journal[1].kind, TxKind::Withdraw);
        assert_eq!(journal[1].prev_txid, Some(journal[0].txid));
        assert_ne!(journal[0].txid, journal[1].txid);
        assert_eq!(
            engine.backend().get(id).unwrap().state,
            AssertionState::Accepted
        );
    }

    #[test]
    fn lifecycle_reject_records_challenge_disprove_punish() {
        let mut engine = engine();
        let id = engine
            .assert(MockEvidence::invalid("bad"), Deadline::from_raw(100))
            .unwrap();
        engine.challenge(id, ChallengerId::new("watcher")).unwrap();
        let settlement = engine.finalize(id).unwrap();
        assert_eq!(settlement.outcome, Outcome::Rejected);

        let kinds: Vec<_> = engine.backend().journal().iter().map(|t| t.kind).collect();
        assert_eq!(
            kinds,
            vec![
                TxKind::Assert,
                TxKind::Challenge,
                TxKind::Disprove,
                TxKind::Punish,
            ]
        );
        // Graph links: each tx points at the previous tip for this assertion.
        let j = engine.backend().journal();
        assert_eq!(j[1].prev_txid, Some(j[0].txid));
        assert_eq!(j[2].prev_txid, Some(j[1].txid));
        assert_eq!(j[3].prev_txid, Some(j[2].txid));
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
}
