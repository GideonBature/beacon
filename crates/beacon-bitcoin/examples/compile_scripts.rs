//! Compile full reject-path journal (Assert→Challenge→Disprove→Punish) to Script.

use beacon_bitcoin::{compile_journal, BitcoinBackend, TxKind};
use beacon_core::{ChallengerId, Deadline, Engine};
use beacon_mock::MockEvidence;

fn main() {
    let mut engine = Engine::new(BitcoinBackend::with_bond(
        beacon_mock::MockConfig::default(),
        10_000,
    ));
    let id = engine
        .assert(MockEvidence::invalid("bad-root"), Deadline::from_raw(100))
        .expect("assert");
    engine
        .challenge(id, ChallengerId::new("watcher"))
        .expect("challenge");
    let _ = engine.finalize(id).expect("finalize");

    println!("compiled journal entries:\n");
    let mut kinds = Vec::new();
    for (txid, result) in compile_journal(engine.backend().journal()) {
        let compiled = result.expect("all intents compile");
        kinds.push(compiled.kind);
        println!("txid={txid}");
        println!("  kind={:?}", compiled.kind);
        println!("  script={}", compiled.script_pubkey);
        println!(
            "  tx: version={:?} locktime={:?} vins={} vouts={}",
            compiled.tx.version,
            compiled.tx.lock_time,
            compiled.tx.input.len(),
            compiled.tx.output.len()
        );
        println!();
    }

    assert_eq!(
        kinds,
        [
            TxKind::Assert,
            TxKind::Challenge,
            TxKind::Disprove,
            TxKind::Punish
        ]
    );
}
