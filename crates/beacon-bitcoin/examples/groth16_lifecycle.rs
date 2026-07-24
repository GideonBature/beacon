//! Cube-shaped stack: Groth16 registry evidence → simulated Bitcoin journal.

use beacon_bitcoin::{BitcoinBackend, TxKind};
use beacon_core::{Deadline, Engine, Instant, Verifiable};
use beacon_groth16::testing::{prove_product_parts, ProductWitness};
use beacon_groth16::{Groth16Statement, VerifyingKeyRegistry};

fn main() {
    let (vk, proof, product) = prove_product_parts(ProductWitness { a: 9, b: 9 });
    let mut registry = VerifyingKeyRegistry::new();
    registry.register("cube-batch-v1", vk);
    let evidence = registry
        .evidence("cube-batch-v1", Groth16Statement::new(vec![product]), proof)
        .expect("resolve vk");
    assert!(evidence.check());
    println!("vk_id={:?} product={product}", evidence.vk_id());

    let mut engine = Engine::new(BitcoinBackend::default());
    let id = engine
        .assert(evidence, Deadline::from_raw(4))
        .expect("assert");
    engine.backend_mut().set_now(Instant::new(4));
    let settlement = engine.finalize(id).expect("finalize");
    println!("settled: {:?}", settlement.outcome);

    println!("\njournal:");
    for tx in engine.backend().journal() {
        println!("  {:?} txid={}", tx.kind, tx.txid);
    }
    assert_eq!(
        engine
            .backend()
            .journal()
            .iter()
            .map(|t| t.kind)
            .collect::<Vec<_>>(),
        vec![TxKind::Assert, TxKind::Withdraw]
    );
}
