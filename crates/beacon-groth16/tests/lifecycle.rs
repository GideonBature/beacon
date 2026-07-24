//! Integration: Groth16 [`Verifiable`] evidence through [`MockBackend`].

use ark_bn254::Fr;
use beacon_core::{AssertionState, ChallengerId, Deadline, Engine, Instant, Outcome, Verifiable};
use beacon_events::ChallengeResult;
use beacon_groth16::testing::{prove_product, with_public_inputs, ProductWitness};
use beacon_mock::MockBackend;

#[test]
fn groth16_accept_without_challenge() {
    let (evidence, _) = prove_product(ProductWitness { a: 3, b: 5 });
    assert!(evidence.check());

    let mut engine = Engine::new(MockBackend::default());
    let id = engine
        .assert(evidence, Deadline::from_raw(10))
        .expect("assert");

    engine.backend_mut().set_now(Instant::new(10));
    let settlement = engine.finalize(id).expect("finalize");
    assert_eq!(settlement.outcome, Outcome::Accepted);
    assert_eq!(
        engine.backend().get(id).unwrap().state,
        AssertionState::Accepted
    );
}

#[test]
fn groth16_reject_on_challenge_when_invalid() {
    let (evidence, product) = prove_product(ProductWitness { a: 6, b: 7 });
    let bad = with_public_inputs(&evidence, vec![product + Fr::from(1u64)]);
    assert!(!bad.check());

    let mut engine = Engine::new(MockBackend::default());
    let id = engine.assert(bad, Deadline::from_raw(50)).expect("assert");

    engine
        .challenge(id, ChallengerId::new("c"))
        .expect("challenge");
    assert_eq!(
        engine.backend().get(id).unwrap().challenge_result,
        Some(ChallengeResult::Disproven)
    );

    let settlement = engine.finalize(id).expect("finalize");
    assert_eq!(settlement.outcome, Outcome::Rejected);
}

#[test]
fn groth16_upheld_challenge_still_accepts() {
    let (evidence, _) = prove_product(ProductWitness { a: 8, b: 9 });
    assert!(evidence.check());

    let mut engine = Engine::new(MockBackend::default());
    let id = engine
        .assert(evidence, Deadline::from_raw(50))
        .expect("assert");
    engine
        .challenge(id, ChallengerId::new("c"))
        .expect("challenge");
    assert_eq!(
        engine.backend().get(id).unwrap().challenge_result,
        Some(ChallengeResult::Upheld)
    );
    let settlement = engine.finalize(id).expect("finalize");
    assert_eq!(settlement.outcome, Outcome::Accepted);
}
