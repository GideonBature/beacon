//! Simulated Bitcoin backend: assert → timeout → withdraw journal.

use beacon_bitcoin::{BitcoinBackend, TxKind};
use beacon_core::{Deadline, Engine, Instant};
use beacon_mock::MockEvidence;

fn main() {
    let mut engine = Engine::new(BitcoinBackend::default());
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

    println!("\nsimulated txs:");
    for tx in engine.backend().journal() {
        println!(
            "  #{:<3} {:<10} txid={} locktime={:?} prev={:?}",
            tx.index,
            format!("{:?}", tx.kind),
            tx.txid,
            tx.locktime,
            tx.prev_txid.map(|p| p.to_string())
        );
    }

    let kinds: Vec<_> = engine.backend().journal().iter().map(|t| t.kind).collect();
    assert_eq!(kinds, vec![TxKind::Assert, TxKind::Withdraw]);
}
