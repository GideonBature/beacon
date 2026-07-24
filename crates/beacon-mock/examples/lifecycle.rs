//! Minimal lifecycle demo: assert → timeout → accept, printing RFC-0003 events.

use beacon_core::{Deadline, Engine, Instant};
use beacon_events::Event;
use beacon_mock::{MockBackend, MockEvidence};

fn main() {
    let mut engine = Engine::new(MockBackend::default());

    let id = engine
        .assert(
            MockEvidence::valid("demo-state-root"),
            Deadline::from_raw(5),
        )
        .expect("assert");

    println!("asserted {id}");

    engine.backend_mut().set_now(Instant::new(5));
    let settlement = engine.finalize(id).expect("finalize");
    println!("settled: {:?}", settlement.outcome);

    println!("\nevents:");
    for event in engine.backend().events() {
        match event {
            Event::AssertionCreated {
                assertion_id,
                challenge_deadline,
            } => {
                println!("  AssertionCreated {assertion_id} deadline={challenge_deadline:?}");
            }
            Event::ChallengeOpened {
                assertion_id,
                challenge_id,
                challenger,
            } => {
                println!(
                    "  ChallengeOpened assertion={assertion_id} challenge={challenge_id} by={challenger}"
                );
            }
            Event::ChallengeResolved {
                assertion_id,
                challenge_id,
                result,
            } => {
                println!(
                    "  ChallengeResolved assertion={assertion_id} challenge={challenge_id} result={result:?}"
                );
            }
            Event::AssertionFinalized {
                assertion_id,
                outcome,
            } => {
                println!("  AssertionFinalized {assertion_id} outcome={outcome:?}");
            }
        }
    }
}
