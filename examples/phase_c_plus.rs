//! Phase C+ – garbled Groth16 verify (Garble → Evaluate).
//!
//! Prefer **release** (debug is very slow):
//!
//! ```bash
//! export CARGO_TARGET_DIR=./target
//! cargo run --release --example phase_c_plus --features gsv --no-default-features
//! cargo run --release --example phase_c_plus --features gsv --no-default-features -- --cheat
//! ```
//!
//! Optional: `--k N` sets DummyCircuit constraints to `2^N` (default 6; use 4 for a quicker smoke).

use beacon::{ClaimMini, EvaluationResult, PhaseCPlusFlow, ShareBundle};
use secp256k1::{Keypair, Secp256k1};
use std::env;
use std::time::Instant;

fn main() {
    let args: Vec<String> = env::args().collect();
    let cheat = args.iter().any(|a| a == "--cheat");
    let k = args
        .windows(2)
        .find(|w| w[0] == "--k")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(beacon::DEFAULT_K);

    println!("=== Beacon Phase C+ – garbled Groth16 ===\n");
    println!("k={k} constraints={} (prefer --release)\n", 1u64 << k);

    let flow = PhaseCPlusFlow::with_share_bundle(ShareBundle::synthetic_from_adaptor_secret(
        &[0xC4; 32],
    ))
    .with_k(k);
    println!("mode={}", flow.name());

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
        println!("Engine cheating: inflating total_out → broken Groth16 public input");
        claim.total_out = 250_000;
    } else {
        println!("Engine honest: valid Groth16 proof");
    }

    let secp = Secp256k1::new();
    let signer = Keypair::new(&secp, &mut rand::thread_rng());

    let t0 = Instant::now();
    let assert_pkg = flow
        .engine_create_assert(&claim, "funding:0", &signer)
        .expect("phase-c+ assert");
    println!(
        "garble+prove in {:.1}s  H(L_invalid)={}",
        t0.elapsed().as_secs_f64(),
        hex::encode(assert_pkg.h_l_invalid)
    );
    println!(
        "  L_invalid={}  proof_should_verify={}",
        hex::encode(assert_pkg.groth16.l_invalid),
        assert_pkg.groth16.proof_should_verify
    );

    let t1 = Instant::now();
    let result = flow
        .challenger_evaluate(
            &claim,
            &assert_pkg.opening,
            &assert_pkg.groth16,
            &assert_pkg.h_l_invalid,
        )
        .expect("evaluate");
    println!("evaluate in {:.1}s", t1.elapsed().as_secs_f64());

    match result {
        EvaluationResult::Valid => {
            println!("Result: VALID – Engine can Timeout");
            let _ = PhaseCPlusFlow::build_timeout("assert:0", "reserve:0", "engine");
        }
        EvaluationResult::Invalid { l_invalid } => {
            println!("Result: INVALID – Disprove with L*={}", hex::encode(l_invalid));
            let _ = PhaseCPlusFlow::build_disprove("assert:0", l_invalid, "slash");
        }
    }

    println!("\nOK — Phase C+ garbled Groth16 path finished.");
}
