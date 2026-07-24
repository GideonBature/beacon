//! Beacon lifecycle events (RFC-0003).
//!
//! Backends SHOULD emit these events in transition order. Delivery and
//! persistence are host concerns until a wire-format RFC exists.

#![forbid(unsafe_code)]

use beacon_core::{AssertionId, ChallengeId, ChallengerId, Deadline, Outcome};

/// Result of resolving a challenge (subject-unambiguous naming).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChallengeResult {
    /// Evidence showed the assertion false — challenger wins on finalize.
    Disproven,
    /// Evidence upheld the assertion — assertion wins on finalize.
    Upheld,
}

/// Lifecycle event emitted by a Beacon backend / engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// T1 — assertion posted; challenge window open.
    AssertionCreated {
        /// New assertion id.
        assertion_id: AssertionId,
        /// Challenge-window deadline.
        challenge_deadline: Deadline,
    },
    /// T3 — challenge opened against an assertion.
    ChallengeOpened {
        /// Assertion under dispute.
        assertion_id: AssertionId,
        /// Challenge id.
        challenge_id: ChallengeId,
        /// Party that opened the challenge.
        challenger: ChallengerId,
    },
    /// Challenge resolved (mock may emit synchronously inside `challenge`).
    ChallengeResolved {
        /// Assertion under dispute.
        assertion_id: AssertionId,
        /// Challenge id.
        challenge_id: ChallengeId,
        /// Disproven or Upheld.
        result: ChallengeResult,
    },
    /// Terminal settlement completed.
    AssertionFinalized {
        /// Settled assertion.
        assertion_id: AssertionId,
        /// Accepted or Rejected.
        outcome: Outcome,
    },
}

/// Receives lifecycle events.
pub trait EventSink {
    /// Handle one event.
    fn emit(&mut self, event: Event);
}

impl EventSink for () {
    fn emit(&mut self, _event: Event) {}
}

/// Records events in memory (tests, CLI, demos).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordingSink {
    events: Vec<Event>,
}

impl RecordingSink {
    /// Create an empty recording sink.
    #[must_use]
    pub const fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Borrow recorded events in emission order.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Drain recorded events.
    #[must_use]
    pub fn take(&mut self) -> Vec<Event> {
        core::mem::take(&mut self.events)
    }

    /// Clear without returning.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl EventSink for RecordingSink {
    fn emit(&mut self, event: Event) {
        self.events.push(event);
    }
}

impl EventSink for Vec<Event> {
    fn emit(&mut self, event: Event) {
        self.push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_core::Instant;

    #[test]
    fn recording_sink_preserves_order() {
        let mut sink = RecordingSink::new();
        let id = AssertionId::new();
        sink.emit(Event::AssertionCreated {
            assertion_id: id,
            challenge_deadline: Deadline::at(Instant::new(10)),
        });
        sink.emit(Event::AssertionFinalized {
            assertion_id: id,
            outcome: Outcome::Accepted,
        });
        assert_eq!(sink.events().len(), 2);
        assert!(matches!(sink.events()[0], Event::AssertionCreated { .. }));
        assert!(matches!(
            sink.events()[1],
            Event::AssertionFinalized {
                outcome: Outcome::Accepted,
                ..
            }
        ));
    }
}
