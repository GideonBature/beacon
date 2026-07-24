//! Groth16 evidence via VK registry through the Beacon mock lifecycle.

use ark_bn254::Fr;
use beacon_core::{ChallengerId, Deadline, Engine, Instant, Outcome, Verifiable};
use beacon_events::{ChallengeResult, Event};
use beacon_groth16::testing::{prove_product_parts, with_public_inputs, ProductWitness};
use beacon_groth16::{Groth16Statement, VerifyingKeyId, VerifyingKeyRegistry};
use beacon_mock::MockBackend;

fn main() {
    let vk_id = VerifyingKeyId::new("toy-product-v1");

    println!("=== registry resolve → accept ===");
    {
        let (vk, proof, product) = prove_product_parts(ProductWitness { a: 7, b: 11 });
        let mut registry = VerifyingKeyRegistry::new();
        registry.register(vk_id.clone(), vk);

        let evidence = registry
            .evidence(vk_id.clone(), Groth16Statement::new(vec![product]), proof)
            .expect("resolve");
        assert!(evidence.check());
        assert_eq!(evidence.vk_id(), Some(&vk_id));
        println!("resolved vk_id={}", evidence.vk_id().unwrap());

        let mut engine = Engine::new(MockBackend::default());
        let id = engine
            .assert(evidence, Deadline::from_raw(3))
            .expect("assert");
        engine.backend_mut().set_now(Instant::new(3));
        let settlement = engine.finalize(id).expect("finalize");
        println!("settled: {:?}", settlement.outcome);
        assert_eq!(settlement.outcome, Outcome::Accepted);
    }

    println!("\n=== registry resolve → challenge reject ===");
    {
        let (vk, proof, product) = prove_product_parts(ProductWitness { a: 2, b: 4 });
        let mut registry = VerifyingKeyRegistry::new();
        registry.register(vk_id.clone(), vk);

        let evidence = registry
            .evidence(vk_id, Groth16Statement::new(vec![product]), proof)
            .expect("resolve");
        let bad = with_public_inputs(&evidence, vec![product + Fr::from(1u64)]);
        assert!(!bad.check());

        let mut engine = Engine::new(MockBackend::default());
        let id = engine.assert(bad, Deadline::from_raw(100)).expect("assert");
        engine
            .challenge(id, ChallengerId::new("watcher"))
            .expect("challenge");
        let settlement = engine.finalize(id).expect("finalize");
        assert_eq!(settlement.outcome, Outcome::Rejected);
        assert!(matches!(
            &engine.backend().events()[2],
            Event::ChallengeResolved {
                result: ChallengeResult::Disproven,
                ..
            }
        ));
        println!("settled: {:?}", settlement.outcome);
    }
}
