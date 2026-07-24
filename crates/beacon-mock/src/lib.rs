//! In-memory [`MockBackend`] — reference [`DisputeBackend`](beacon_core::DisputeBackend).
//!
//! Drives assertions through the RFC-0004 lifecycle without Bitcoin, networking,
//! or named proof systems. Intended as the executable specification for tests
//! that every future backend (including Bitcoin) must also satisfy.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use beacon_core::{
    AssertionId, AssertionState, BackendId, ChallengeId, ChallengerId, Deadline, DisputeBackend,
    Error, Instant, Outcome, Result, Settlement, Verifiable,
};

/// Result of resolving a challenge (RFC-0003 / RFC-0004 naming).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChallengeResult {
    /// Evidence failed `check` — challenger wins on finalize.
    Disproven,
    /// Evidence passed `check` — assertion wins on finalize.
    Upheld,
}

#[derive(Clone, Debug)]
struct OpenChallenge {
    #[allow(dead_code)] // retained for events / inspection in later commits
    id: ChallengeId,
    #[allow(dead_code)]
    challenger: ChallengerId,
    result: ChallengeResult,
    #[allow(dead_code)]
    dispute_deadline: Deadline,
}

struct Record<E> {
    evidence: E,
    deadline: Deadline,
    dispute_deadline: Option<Deadline>,
    state: AssertionState,
    settled: bool,
    challenge: Option<OpenChallenge>,
}

impl<E: std::fmt::Debug> std::fmt::Debug for Record<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("evidence", &self.evidence)
            .field("deadline", &self.deadline)
            .field("dispute_deadline", &self.dispute_deadline)
            .field("state", &self.state)
            .field("settled", &self.settled)
            .field("challenge", &self.challenge)
            .finish()
    }
}

/// Read-only view of an assertion stored in the mock backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionView {
    /// Assertion id.
    pub id: AssertionId,
    /// Lifecycle status.
    pub state: AssertionState,
    /// Whether settlement finalization completed.
    pub settled: bool,
    /// Challenge-window deadline.
    pub deadline: Deadline,
    /// Challenge resolution, if a challenge was opened.
    pub challenge_result: Option<ChallengeResult>,
}

impl AssertionView {
    /// Returns `true` if the assertion is terminally settled.
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        self.settled && self.state.is_terminal()
    }
}

/// Configuration for [`MockBackend`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockConfig {
    /// Logical duration after a challenge opens before T6 timeout applies.
    ///
    /// The v1 mock resolves `check()` synchronously inside `challenge`, so this
    /// is only relevant if resolution is later made asynchronous.
    pub dispute_window: u64,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self { dispute_window: 10 }
    }
}

/// In-memory dispute backend (Milestone 1).
pub struct MockBackend<E> {
    config: MockConfig,
    now: Instant,
    records: HashMap<AssertionId, Record<E>>,
}

impl<E: std::fmt::Debug> std::fmt::Debug for MockBackend<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockBackend")
            .field("config", &self.config)
            .field("now", &self.now)
            .field("records", &self.records)
            .finish()
    }
}

impl<E> Default for MockBackend<E> {
    fn default() -> Self {
        Self::new(MockConfig::default())
    }
}

impl<E> MockBackend<E> {
    /// Create a mock backend with the given config. Clock starts at `0`.
    #[must_use]
    pub fn new(config: MockConfig) -> Self {
        Self {
            config,
            now: Instant::new(0),
            records: HashMap::new(),
        }
    }

    /// Current logical time.
    #[must_use]
    pub const fn now(&self) -> Instant {
        self.now
    }

    /// Set the logical clock (monotonicity is the caller's responsibility).
    pub const fn set_now(&mut self, now: Instant) {
        self.now = now;
    }

    /// Advance the logical clock by `delta` ticks.
    pub const fn advance(&mut self, delta: u64) {
        self.now.0 = self.now.0.saturating_add(delta);
    }

    /// Backend id string used for assertions created here.
    #[must_use]
    pub fn backend_id() -> BackendId {
        BackendId::new("mock")
    }
}

impl<E: Verifiable> MockBackend<E> {
    /// Inspect a stored assertion.
    #[must_use]
    pub fn get(&self, id: AssertionId) -> Option<AssertionView> {
        let record = self.records.get(&id)?;
        Some(AssertionView {
            id,
            state: record.state,
            settled: record.settled,
            deadline: record.deadline,
            challenge_result: record.challenge.as_ref().map(|c| c.result),
        })
    }
}

impl<E: Verifiable> DisputeBackend for MockBackend<E> {
    type Evidence = E;

    fn assert(&mut self, evidence: Self::Evidence, deadline: Deadline) -> Result<AssertionId> {
        let id = AssertionId::new();
        self.records.insert(
            id,
            Record {
                evidence,
                deadline,
                dispute_deadline: None,
                state: AssertionState::Asserted,
                settled: false,
                challenge: None,
            },
        );
        Ok(id)
    }

    fn challenge(&mut self, assertion: AssertionId, challenger: ChallengerId) -> Result<()> {
        let now = self.now;
        let dispute_window = self.config.dispute_window;

        let record = self.records.get_mut(&assertion).ok_or(Error::NotFound)?;

        if record.settled {
            return Err(Error::AlreadySettled);
        }
        if record.state != AssertionState::Asserted {
            return Err(Error::InvalidState {
                current: record.state,
            });
        }
        if record.deadline.is_reached(now) {
            return Err(Error::ChallengeWindowClosed);
        }

        let result = if record.evidence.check() {
            ChallengeResult::Upheld
        } else {
            ChallengeResult::Disproven
        };

        let dispute_deadline = Deadline::from_raw(now.get().saturating_add(dispute_window));
        record.state = AssertionState::Disputing;
        record.dispute_deadline = Some(dispute_deadline);
        record.challenge = Some(OpenChallenge {
            id: ChallengeId::new(),
            challenger,
            result,
            dispute_deadline,
        });
        Ok(())
    }

    fn finalize(&mut self, assertion: AssertionId) -> Result<Settlement> {
        let now = self.now;
        let record = self.records.get_mut(&assertion).ok_or(Error::NotFound)?;

        if record.settled {
            return Err(Error::AlreadySettled);
        }

        let outcome = match record.state {
            AssertionState::Asserted => {
                if record.deadline.is_reached(now) {
                    Outcome::Accepted
                } else {
                    return Err(Error::DisputePending);
                }
            }
            AssertionState::Disputing => {
                let challenge = record.challenge.as_ref().ok_or(Error::InvalidState {
                    current: AssertionState::Disputing,
                })?;
                match challenge.result {
                    ChallengeResult::Disproven => Outcome::Rejected,
                    ChallengeResult::Upheld => Outcome::Accepted,
                }
            }
            AssertionState::Accepted | AssertionState::Rejected => {
                return Err(Error::AlreadySettled);
            }
        };

        record.state = match outcome {
            Outcome::Accepted => AssertionState::Accepted,
            Outcome::Rejected => AssertionState::Rejected,
        };
        record.settled = true;

        Ok(Settlement::new(assertion, outcome))
    }
}

/// Simple evidence for tests and examples: a statement plus a validity bit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockEvidence {
    statement: String,
    valid: bool,
}

impl MockEvidence {
    /// Evidence that will pass [`Verifiable::check`].
    #[must_use]
    pub fn valid(statement: impl Into<String>) -> Self {
        Self {
            statement: statement.into(),
            valid: true,
        }
    }

    /// Evidence that will fail [`Verifiable::check`] (successful challenge).
    #[must_use]
    pub fn invalid(statement: impl Into<String>) -> Self {
        Self {
            statement: statement.into(),
            valid: false,
        }
    }
}

impl Verifiable for MockEvidence {
    type Statement = String;

    fn statement(&self) -> &Self::Statement {
        &self.statement
    }

    fn check(&self) -> bool {
        self.valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_core::Engine;

    fn engine() -> Engine<MockBackend<MockEvidence>> {
        Engine::new(MockBackend::default())
    }

    #[test]
    fn lifecycle_accept_without_challenge() {
        let mut engine = engine();
        let id = engine
            .assert(MockEvidence::valid("root-1"), Deadline::from_raw(10))
            .unwrap();

        let view = engine.backend().get(id).unwrap();
        assert_eq!(view.state, AssertionState::Asserted);
        assert!(!view.settled);

        // Too early to finalize.
        assert_eq!(engine.finalize(id), Err(Error::DisputePending));

        engine.backend_mut().set_now(Instant::new(10));
        let settlement = engine.finalize(id).unwrap();
        assert!(settlement.is_accepted());
        assert_eq!(settlement.assertion_id, id);

        let view = engine.backend().get(id).unwrap();
        assert_eq!(view.state, AssertionState::Accepted);
        assert!(view.settled);
        assert!(view.is_settled());
    }

    #[test]
    fn lifecycle_reject_on_successful_challenge() {
        let mut engine = engine();
        let id = engine
            .assert(MockEvidence::invalid("root-bad"), Deadline::from_raw(100))
            .unwrap();

        engine
            .challenge(id, ChallengerId::new("challenger-1"))
            .unwrap();

        let view = engine.backend().get(id).unwrap();
        assert_eq!(view.state, AssertionState::Disputing);
        assert_eq!(view.challenge_result, Some(ChallengeResult::Disproven));

        let settlement = engine.finalize(id).unwrap();
        assert!(settlement.is_rejected());

        let view = engine.backend().get(id).unwrap();
        assert_eq!(view.state, AssertionState::Rejected);
        assert!(view.settled);
    }

    #[test]
    fn rejects_invalid_transition_after_settlement() {
        let mut engine = engine();
        let id = engine
            .assert(MockEvidence::valid("root-1"), Deadline::from_raw(5))
            .unwrap();

        engine.backend_mut().set_now(Instant::new(5));
        let _ = engine.finalize(id).unwrap();

        // Challenge after settle must fail.
        assert_eq!(
            engine.challenge(id, ChallengerId::new("late")),
            Err(Error::AlreadySettled)
        );

        // Finalize again must fail (no double settlement).
        assert_eq!(engine.finalize(id), Err(Error::AlreadySettled));
    }

    #[test]
    fn challenge_after_deadline_fails() {
        let mut engine = engine();
        let id = engine
            .assert(MockEvidence::invalid("x"), Deadline::from_raw(3))
            .unwrap();
        engine.backend_mut().set_now(Instant::new(3));
        assert_eq!(
            engine.challenge(id, ChallengerId::new("c")),
            Err(Error::ChallengeWindowClosed)
        );
    }

    #[test]
    fn upheld_challenge_accepts_on_finalize() {
        let mut engine = engine();
        let id = engine
            .assert(MockEvidence::valid("ok"), Deadline::from_raw(50))
            .unwrap();
        engine.challenge(id, ChallengerId::new("c")).unwrap();
        assert_eq!(
            engine.backend().get(id).unwrap().challenge_result,
            Some(ChallengeResult::Upheld)
        );
        let settlement = engine.finalize(id).unwrap();
        assert!(settlement.is_accepted());
    }
}
