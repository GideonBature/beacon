//! Bitcoin-shaped [`DisputeBackend`](beacon_core::DisputeBackend) skeleton.
//!
//! # What this is
//!
//! A lifecycle-compatible backend that records a **simulated** Bitcoin
//! transaction journal aligned with RFC-0006:
//!
//! | Protocol step | Journal entry |
//! |---------------|---------------|
//! | `assert` | [`TxKind::Assert`] |
//! | `challenge` | [`TxKind::Challenge`] (+ [`TxKind::Disprove`] if evidence fails) |
//! | `finalize` → Accepted | [`TxKind::Withdraw`] |
//! | `finalize` → Rejected | [`TxKind::Punish`] |
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

use beacon_core::{
    AssertionId, BackendId, ChallengerId, Deadline, DisputeBackend, Instant, Result, Settlement,
    Verifiable,
};
use beacon_events::{ChallengeResult, Event, RecordingSink};
use beacon_mock::{AssertionView, MockBackend, MockConfig};

/// Kind of simulated Bitcoin transaction (RFC-0006 mapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TxKind {
    /// Assertion / commit broadcast.
    Assert,
    /// Challenge opened on-chain.
    Challenge,
    /// Disprove / fraud path (challenger showed invalid evidence).
    Disprove,
    /// Timeout / withdraw after accepted settlement.
    Withdraw,
    /// Punishment finalization after rejected settlement.
    Punish,
}

/// One simulated chain action tied to an assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulatedTx {
    /// Transaction role in the dispute graph.
    pub kind: TxKind,
    /// Assertion this action belongs to.
    pub assertion_id: AssertionId,
    /// Monotonic simulated tx index (stand-in for txid ordering).
    pub index: u64,
}

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

    fn push_tx(&mut self, kind: TxKind, assertion_id: AssertionId) {
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        self.journal.push(SimulatedTx {
            kind,
            assertion_id,
            index,
        });
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
        self.push_tx(TxKind::Assert, id);
        Ok(id)
    }

    fn challenge(&mut self, assertion: AssertionId, challenger: ChallengerId) -> Result<()> {
        self.mock.challenge(assertion, challenger)?;
        self.push_tx(TxKind::Challenge, assertion);
        if self.mock.get(assertion).and_then(|v| v.challenge_result)
            == Some(ChallengeResult::Disproven)
        {
            self.push_tx(TxKind::Disprove, assertion);
        }
        Ok(())
    }

    fn finalize(&mut self, assertion: AssertionId) -> Result<Settlement> {
        let settlement = self.mock.finalize(assertion)?;
        match settlement.outcome {
            beacon_core::Outcome::Accepted => self.push_tx(TxKind::Withdraw, assertion),
            beacon_core::Outcome::Rejected => self.push_tx(TxKind::Punish, assertion),
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

        assert_eq!(
            engine.backend().journal(),
            &[SimulatedTx {
                kind: TxKind::Assert,
                assertion_id: id,
                index: 0,
            }]
        );

        assert_eq!(engine.finalize(id), Err(Error::DisputePending));
        engine.backend_mut().set_now(Instant::new(10));
        let settlement = engine.finalize(id).unwrap();
        assert!(settlement.is_accepted());

        let kinds: Vec<_> = engine.backend().journal().iter().map(|t| t.kind).collect();
        assert_eq!(kinds, vec![TxKind::Assert, TxKind::Withdraw]);
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
