//! Beacon Phase A driver — simulation or live regtest.
//!
//! ```bash
//! cargo run --example phase_a_driver
//! cargo run --example phase_a_driver -- --cheat
//! cargo run --example phase_a_driver -- --gsv --cheat
//! cargo run --example phase_a_driver -- --regtest
//! cargo run --example phase_a_driver -- --regtest --cheat
//! ```

use beacon::{
    run_phase_a_regtest, ClaimMini, ClaimMiniBackend, EvaluationResult, GarbledSnarkBackend,
    PhaseAFlow, RegtestOutcome,
};
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    let cheat = args.iter().any(|a| a == "--cheat");
    let use_gsv = args.iter().any(|a| a == "--gsv");
    let regtest = args.iter().any(|a| a == "--regtest");

    println!("=== Beacon Phase A Driver ===\n");

    if regtest {
        if use_gsv {
            eprintln!("note: --regtest currently uses ClaimMiniBackend (on-chain path is backend-agnostic)");
        }
        match run_phase_a_regtest(cheat) {
            Ok(RegtestOutcome::Accepted {
                assert_txid,
                timeout_txid,
            }) => {
                println!("\nPASS Accepted");
                println!("  assert_txid={assert_txid}");
                println!("  timeout_txid={timeout_txid}");
            }
            Ok(RegtestOutcome::Rejected {
                assert_txid,
                disprove_txid,
            }) => {
                println!("\nPASS Rejected (challenger Disprove)");
                println!("  assert_txid={assert_txid}");
                println!("  disprove_txid={disprove_txid}");
            }
            Err(e) => {
                eprintln!("regtest failed: {e}");
                process::exit(1);
            }
        }
        return;
    }

    let mut claim = ClaimMini::make_valid(
        [0x01; 32],
        100_000,
        40_000,
        [0x10; 32],
        [0x11; 32],
        [0x12; 32],
        [0x13; 32],
    );

    if cheat {
        println!("Engine is cheating: inflating total_out");
        claim.total_out = 250_000;
    } else {
        println!("Engine is honest");
    }

    if use_gsv {
        run_sim(PhaseAFlow::new(GarbledSnarkBackend), &claim);
    } else {
        run_sim(PhaseAFlow::new(ClaimMiniBackend), &claim);
    }
}

fn run_sim<B: beacon::CircuitBackend<Claim = ClaimMini>>(flow: PhaseAFlow<B>, claim: &ClaimMini) {
    println!("backend={}", flow.backend().name());

    let (_assert_tmpl, opening, h_l_invalid) =
        flow.engine_create_assert(claim, "funding:txid:0");
    println!("H(L_invalid): {}", hex::encode(h_l_invalid));
    println!("Opening seed: {}", hex::encode(opening.seed));

    println!("\n--- Challenger evaluates ---");
    match flow.challenger_evaluate(claim, &opening, &h_l_invalid) {
        EvaluationResult::Valid => {
            println!("Result: VALID – Engine can Timeout later");
            let _timeout =
                PhaseAFlow::<B>::build_timeout("assert_txid:0", "reserve:0", "engine_pk");
        }
        EvaluationResult::Invalid { l_invalid } => {
            println!("Result: INVALID");
            println!("L_invalid: {}", hex::encode(l_invalid));
            let _disprove =
                PhaseAFlow::<B>::build_disprove("assert_txid:0", l_invalid, "slash_addr");
            println!("Challenger can now broadcast Disprove");
        }
    }
    println!("\n=== Done ===");
}
