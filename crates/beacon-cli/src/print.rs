//! Shared demo printing helpers.

use beacon_bitcoin::{compile_journal, SimulatedTx};
use beacon_core::Outcome;
use beacon_events::Event;

pub(crate) fn print_settlement(outcome: Outcome) {
    match outcome {
        Outcome::Accepted => println!("settled: Accepted (assertion wins)"),
        Outcome::Rejected => println!("settled: Rejected (challenger wins)"),
    }
}

pub(crate) fn print_events(events: &[Event]) {
    println!("\nevents:");
    for event in events {
        print_event(event);
    }
}

pub(crate) fn print_event(event: &Event) {
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

pub(crate) fn print_journal(journal: &[SimulatedTx]) {
    println!("\nsimulated txs:");
    for tx in journal {
        println!(
            "  #{:<3} {:<10} txid={} intent={:?} locktime={:?} prev={:?}",
            tx.index,
            format!("{:?}", tx.kind),
            tx.txid,
            tx.template.intent,
            tx.locktime,
            tx.prev_txid.map(|p| p.to_string())
        );
    }
}

/// Compile journal templates to Script skeletons (every [`ScriptIntent`](beacon_bitcoin::ScriptIntent)).
pub(crate) fn print_compiled(journal: &[SimulatedTx]) {
    println!("\ncompiled scripts:");
    for (txid, result) in compile_journal(journal) {
        match result {
            Ok(compiled) => {
                println!(
                    "  {} {:?}: {} (vins={} vouts={} locktime={:?})",
                    txid,
                    compiled.kind,
                    compiled.script_pubkey,
                    compiled.tx.input.len(),
                    compiled.tx.output.len(),
                    compiled.tx.lock_time
                );
            }
            Err(err) => println!("  {txid}: {err}"),
        }
    }
}
