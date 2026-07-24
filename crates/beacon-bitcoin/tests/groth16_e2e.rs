//! End-to-end: Groth16 evidence through the simulated Bitcoin backend.

use ark_bn254::Fr;
use beacon_bitcoin::{BitcoinBackend, TxKind};
use beacon_core::{ChallengerId, Deadline, Engine, Instant, Outcome, Verifiable};
use beacon_groth16::testing::{prove_product_parts, with_public_inputs, ProductWitness};
use beacon_groth16::{Groth16Statement, VerifyingKeyId, VerifyingKeyRegistry};

#[test]
fn groth16_bitcoin_accept_withdraw() {
    let (vk, proof, product) = prove_product_parts(ProductWitness { a: 3, b: 5 });
    let mut registry = VerifyingKeyRegistry::new();
    let vk_id = VerifyingKeyId::new("product-v1");
    registry.register(vk_id.clone(), vk);
    let evidence = registry
        .evidence(vk_id, Groth16Statement::new(vec![product]), proof)
        .unwrap();
    assert!(evidence.check());

    let mut engine = Engine::new(BitcoinBackend::default());
    let id = engine
        .assert(evidence, Deadline::from_raw(8))
        .expect("assert");
    engine.backend_mut().set_now(Instant::new(8));
    let settlement = engine.finalize(id).expect("finalize");
    assert_eq!(settlement.outcome, Outcome::Accepted);

    let kinds: Vec<_> = engine.backend().journal().iter().map(|t| t.kind).collect();
    assert_eq!(kinds, vec![TxKind::Assert, TxKind::Withdraw]);
    assert!(engine.backend().journal()[0].locktime.is_some());
}

#[test]
fn groth16_bitcoin_reject_disprove_punish() {
    let (vk, proof, product) = prove_product_parts(ProductWitness { a: 6, b: 7 });
    let mut registry = VerifyingKeyRegistry::new();
    registry.register("product-v1", vk);
    let evidence = registry
        .evidence("product-v1", Groth16Statement::new(vec![product]), proof)
        .unwrap();
    let bad = with_public_inputs(&evidence, vec![product + Fr::from(1u64)]);
    assert!(!bad.check());

    let mut engine = Engine::new(BitcoinBackend::default());
    let id = engine.assert(bad, Deadline::from_raw(40)).expect("assert");
    engine
        .challenge(id, ChallengerId::new("watcher"))
        .expect("challenge");
    let settlement = engine.finalize(id).expect("finalize");
    assert_eq!(settlement.outcome, Outcome::Rejected);

    let kinds: Vec<_> = engine.backend().journal().iter().map(|t| t.kind).collect();
    assert_eq!(
        kinds,
        vec![
            TxKind::Assert,
            TxKind::Challenge,
            TxKind::Disprove,
            TxKind::Punish
        ]
    );
}
