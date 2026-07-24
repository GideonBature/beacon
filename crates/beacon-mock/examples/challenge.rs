//! Challenge path demo: invalid evidence → challenge → reject.

use beacon_core::{ChallengerId, Deadline, Engine};
use beacon_events::Event;
use beacon_mock::{MockBackend, MockEvidence};

fn main() {
    let mut engine = Engine::new(MockBackend::default());

    let id = engine
        .assert(
            MockEvidence::invalid("bad-state-root"),
            Deadline::from_raw(100),
        )
        .expect("assert");
    println!("asserted {id}");

    engine
        .challenge(id, ChallengerId::new("watcher-1"))
        .expect("challenge");
    println!("challenged");

    let settlement = engine.finalize(id).expect("finalize");
    println!("settled: {:?}", settlement.outcome);

    println!("\nevents:");
    for event in engine.backend().events() {
        match event {
            Event::AssertionCreated { .. } => println!("  AssertionCreated"),
            Event::ChallengeOpened { challenger, .. } => {
                println!("  ChallengeOpened by={challenger}");
            }
            Event::ChallengeResolved { result, .. } => {
                println!("  ChallengeResolved {result:?}");
            }
            Event::AssertionFinalized { outcome, .. } => {
                println!("  AssertionFinalized {outcome:?}");
            }
        }
    }
}
