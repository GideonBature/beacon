//! Beacon Phase A driver — switchable circuit backend.
//!
//! ```bash
//! cargo run --example phase_a_driver              # claim-mini
//! cargo run --example phase_a_driver -- --gsv     # garbled-snark-verifier stand-in
//! cargo run --example phase_a_driver -- --gsv --cheat
//! ```

use beacon::{
    ClaimMini, ClaimMiniBackend, EvaluationResult, GarbledSnarkBackend, PhaseAFlow,
};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let cheat = args.iter().any(|a| a == "--cheat");
    let use_gsv = args.iter().any(|a| a == "--gsv");

    println!("=== Beacon Phase A Driver ===\n");

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
        run(PhaseAFlow::new(GarbledSnarkBackend), &claim);
    } else {
        run(PhaseAFlow::new(ClaimMiniBackend), &claim);
    }
}

fn run<B: beacon::CircuitBackend<Claim = ClaimMini>>(flow: PhaseAFlow<B>, claim: &ClaimMini) {
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
