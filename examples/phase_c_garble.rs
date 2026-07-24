//! Phase C garble → evaluate smoke (requires `gsv`).
//!
//! ```bash
//! cargo run --example phase_c_garble --features gsv
//! ```

use beacon::{ClaimMini, EvaluationResult, PhaseCFlow, ShareBundle};
use secp256k1::{Keypair, Secp256k1};

fn main() {
    println!("=== Beacon Phase C – garbled Evaluate ===\n");

    let flow = PhaseCFlow::with_share_bundle(ShareBundle::synthetic_from_adaptor_secret(
        &[0x42; 32],
    ));
    println!("mode={}", flow.name());

    let secp = Secp256k1::new();
    let signer = Keypair::new(&secp, &mut rand::thread_rng());

    let mut claim = ClaimMini::make_valid(
        [0x01; 32],
        100_000,
        40_000,
        [0x10; 32],
        [0x11; 32],
        [0x12; 32],
        [0x13; 32],
    );

    let (_t, opening, h) = flow
        .engine_create_assert(&claim, "funding:0", &signer)
        .expect("assert");
    println!("honest H(L_invalid)={}", hex::encode(h));
    match flow.challenger_evaluate(&claim, &opening, &h) {
        EvaluationResult::Valid => println!("honest → Valid"),
        EvaluationResult::Invalid { .. } => panic!("expected Valid"),
    }

    claim.total_out = 250_000;
    let (_t, opening, h) = flow
        .engine_create_assert(&claim, "funding:1", &signer)
        .expect("assert");
    println!("cheat  H(L_invalid)={}", hex::encode(h));
    match flow.challenger_evaluate(&claim, &opening, &h) {
        EvaluationResult::Invalid { l_invalid } => {
            println!("cheat  → Invalid L*={}", hex::encode(l_invalid));
        }
        EvaluationResult::Valid => panic!("expected Invalid"),
    }

    println!("\nOK — Phase C garble/evaluate path works.");
}
