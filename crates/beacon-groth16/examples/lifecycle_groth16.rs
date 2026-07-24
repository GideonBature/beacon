//! Groth16 evidence through the Beacon mock lifecycle (accept + reject paths).

use ark_bn254::Fr;
use beacon_core::{ChallengerId, Deadline, Engine, Instant, Outcome, Verifiable};
use beacon_events::{ChallengeResult, Event};
use beacon_groth16::testing::{prove_product, with_public_inputs, ProductWitness};
use beacon_mock::MockBackend;

fn main() {
    println!("=== accept without challenge (valid Groth16) ===");
    {
        let (evidence, product) = prove_product(ProductWitness { a: 7, b: 11 });
        println!("public product = {product}");
        assert!(evidence.check(), "proof must verify");

        let mut engine = Engine::new(MockBackend::default());
        let id = engine
            .assert(evidence, Deadline::from_raw(3))
            .expect("assert");
        println!("asserted {id}");

        engine.backend_mut().set_now(Instant::new(3));
        let settlement = engine.finalize(id).expect("finalize");
        println!("settled: {:?}", settlement.outcome);
        assert_eq!(settlement.outcome, Outcome::Accepted);

        for event in engine.backend().events() {
            println!("  {event:?}");
        }
    }

    println!("\n=== reject via challenge (tampered public input) ===");
    {
        let (evidence, product) = prove_product(ProductWitness { a: 2, b: 4 });
        let bad = with_public_inputs(&evidence, vec![product + Fr::from(1u64)]);
        assert!(!bad.check(), "tampered statement must fail verify");

        let mut engine = Engine::new(MockBackend::default());
        let id = engine.assert(bad, Deadline::from_raw(100)).expect("assert");
        engine
            .challenge(id, ChallengerId::new("watcher"))
            .expect("challenge");
        let settlement = engine.finalize(id).expect("finalize");
        println!("settled: {:?}", settlement.outcome);
        assert_eq!(settlement.outcome, Outcome::Rejected);

        let events = engine.backend().events();
        assert!(matches!(
            &events[2],
            Event::ChallengeResolved {
                result: ChallengeResult::Disproven,
                ..
            }
        ));
        for event in events {
            println!("  {event:?}");
        }
    }
}
