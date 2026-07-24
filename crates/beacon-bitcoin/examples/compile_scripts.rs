//! Compile Assert → Withdraw templates to Bitcoin Script skeletons.

use beacon_bitcoin::{compile, compile_journal, BitcoinBackend, ScriptIntent, TxKind};
use beacon_core::{Deadline, Engine, Instant};
use beacon_mock::MockEvidence;

fn main() {
    let mut engine = Engine::new(BitcoinBackend::with_bond(
        beacon_mock::MockConfig::default(),
        10_000,
    ));
    let id = engine
        .assert(MockEvidence::valid("root"), Deadline::from_raw(20))
        .expect("assert");
    engine.backend_mut().set_now(Instant::new(20));
    let _ = engine.finalize(id).expect("finalize");

    println!("compiled journal entries:\n");
    for (txid, result) in compile_journal(engine.backend().journal()) {
        match result {
            Ok(compiled) => {
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
                if compiled.kind == TxKind::Assert {
                    assert!(compiled.script_pubkey.is_op_return());
                    assert_eq!(compiled.tx.output.len(), 2);
                }
                if let ScriptIntent::WithdrawTimeout { .. } =
                    engine.backend().journal().last().unwrap().template.intent
                {
                    // last entry withdraw
                }
                println!();
            }
            Err(err) => println!("txid={txid} compile error: {err}"),
        }
    }

    // Sanity: both assert + withdraw compile.
    let compiled = compile_journal(engine.backend().journal());
    assert!(compiled.iter().all(|(_, r)| r.is_ok()));
    let _ = compile;
}
