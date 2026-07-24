//! Beacon Phase A / B driver — simulation or live regtest.
//!
//! ```bash
//! cargo run --example phase_a_driver
//! cargo run --example phase_a_driver -- --cheat
//! cargo run --example phase_a_driver -- --adaptor
//! cargo run --example phase_a_driver -- --adaptor --cheat
//! cargo run --example phase_a_driver -- --gsv --cheat
//! cargo run --example phase_a_driver -- --regtest
//! cargo run --example phase_a_driver -- --adaptor --regtest --cheat
//! cargo run --example phase_a_driver -- --phase-c
//! cargo run --example phase_a_driver -- --phase-c --cheat
//! # Phase C+ (garbled Groth16) — prefer the dedicated release example:
//! #   cargo run --release --example phase_c_plus --features gsv --no-default-features
//! cargo run --example phase_a_driver --features gsv -- --phase-c-plus --k 4
//! ```

use beacon::{
    run_phase_a_regtest, run_phase_b_regtest, run_phase_c_regtest, ClaimMini, ClaimMiniBackend,
    EvaluationResult, GarbledSnarkBackend, PhaseAFlow, PhaseBFlow, PhaseCFlow, RegtestOutcome,
    ShareBundle,
};
use secp256k1::{Keypair, Secp256k1};
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    let cheat = args.iter().any(|a| a == "--cheat");
    let use_gsv = args.iter().any(|a| a == "--gsv");
    let adaptor = args.iter().any(|a| a == "--adaptor");
    let phase_c = args.iter().any(|a| a == "--phase-c");
    let phase_c_plus = args.iter().any(|a| a == "--phase-c-plus");
    let regtest = args.iter().any(|a| a == "--regtest");
    let k = args
        .windows(2)
        .find(|w| w[0] == "--k")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(6u32);

    let phase = if phase_c_plus {
        "C+ (garbled Groth16)"
    } else if phase_c {
        "C (VSSS + Evaluate)"
    } else if adaptor {
        "B (adaptor)"
    } else {
        "A (direct seed)"
    };
    println!("=== Beacon Phase {phase} Driver ===\n");

    if regtest {
        if phase_c_plus {
            eprintln!(
                "note: --phase-c-plus --regtest uses Phase C adaptor+hashlock on-chain; \
                 run `phase_c_plus` example for full Groth16 Evaluate"
            );
        }
        if use_gsv && !phase_c && !phase_c_plus {
            eprintln!(
                "note: --regtest currently uses ClaimMiniBackend (on-chain path is backend-agnostic)"
            );
        }
        let result = if phase_c || phase_c_plus {
            run_phase_c_regtest(cheat)
        } else if adaptor {
            run_phase_b_regtest(cheat)
        } else {
            run_phase_a_regtest(cheat)
        };
        match result {
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

    if phase_c_plus {
        run_sim_c_plus(&claim, k);
    } else if phase_c {
        run_sim_c(&claim);
    } else if adaptor {
        if use_gsv {
            run_sim_b(PhaseBFlow::new(GarbledSnarkBackend), &claim);
        } else {
            run_sim_b(PhaseBFlow::new(ClaimMiniBackend), &claim);
        }
    } else if use_gsv {
        run_sim_a(PhaseAFlow::new(GarbledSnarkBackend), &claim);
    } else {
        run_sim_a(PhaseAFlow::new(ClaimMiniBackend), &claim);
    }
}

fn run_sim_a<B: beacon::CircuitBackend<Claim = ClaimMini>>(flow: PhaseAFlow<B>, claim: &ClaimMini) {
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

fn run_sim_b<B: beacon::CircuitBackend<Claim = ClaimMini>>(flow: PhaseBFlow<B>, claim: &ClaimMini) {
    println!("backend={}", flow.backend().name());

    let secp = Secp256k1::new();
    let signer = Keypair::new(&secp, &mut rand::thread_rng());
    let (_assert_tmpl, opening, h_l_invalid) = flow
        .engine_create_assert(claim, "funding:txid:0", &signer)
        .expect("adaptor opening");

    let labels = opening.derive_label_material().expect("extract labels");
    println!("H(L_invalid): {}", hex::encode(h_l_invalid));
    println!("Adaptor point T: {}", hex::encode(opening.adaptor_point));
    println!("Extracted label material: {}", hex::encode(labels));

    println!("\n--- Challenger evaluates (after adaptor extract) ---");
    match flow.challenger_evaluate(claim, &opening, &h_l_invalid) {
        EvaluationResult::Valid => {
            println!("Result: VALID – Engine can Timeout later");
            let _timeout =
                PhaseBFlow::<B>::build_timeout("assert_txid:0", "reserve:0", "engine_pk");
        }
        EvaluationResult::Invalid { l_invalid } => {
            println!("Result: INVALID");
            println!("L_invalid: {}", hex::encode(l_invalid));
            let _disprove =
                PhaseBFlow::<B>::build_disprove("assert_txid:0", l_invalid, "slash_addr");
            println!("Challenger can now broadcast Disprove");
        }
    }
    println!("\n=== Done ===");
}

fn run_sim_c(claim: &ClaimMini) {
    let bundle = ShareBundle::synthetic_from_adaptor_secret(&[0xC3; 32]);
    let flow = PhaseCFlow::with_share_bundle(bundle);
    println!("mode={}", flow.name());

    let secp = Secp256k1::new();
    let signer = Keypair::new(&secp, &mut rand::thread_rng());
    let (_assert_tmpl, opening, h_l_invalid) = flow
        .engine_create_assert(claim, "funding:txid:0", &signer)
        .expect("phase-c assert");

    let labels = opening.derive_label_material().expect("extract labels");
    println!("H(L_invalid): {}", hex::encode(h_l_invalid));
    println!("Adaptor point T: {}", hex::encode(opening.adaptor_point));
    println!("Adaptor label material: {}", hex::encode(labels));

    println!("\n--- Challenger: reconstruct + garbled Evaluate ---");
    match flow.challenger_evaluate(claim, &opening, &h_l_invalid) {
        EvaluationResult::Valid => {
            println!("Result: VALID – Engine can Timeout later");
            let _timeout = PhaseCFlow::build_timeout("assert_txid:0", "reserve:0", "engine_pk");
        }
        EvaluationResult::Invalid { l_invalid } => {
            println!("Result: INVALID");
            println!("L_invalid: {}", hex::encode(l_invalid));
            let _disprove = PhaseCFlow::build_disprove("assert_txid:0", l_invalid, "slash_addr");
            println!("Challenger can now broadcast Disprove");
        }
    }
    println!("\n=== Done ===");
}

fn run_sim_c_plus(claim: &ClaimMini, k: u32) {
    #[cfg(not(feature = "gsv"))]
    {
        let _ = (claim, k);
        eprintln!(
            "error: --phase-c-plus requires the `gsv` feature.\n\
             Try:\n  cargo run --release --example phase_c_plus --features gsv --no-default-features -- --k {k}"
        );
        process::exit(2);
    }
    #[cfg(feature = "gsv")]
    {
        use beacon::PhaseCPlusFlow;
        use std::time::Instant;

        eprintln!("note: full Groth16 garble/evaluate is heavy — prefer --release and --k 4 for smoke");
        let flow = PhaseCPlusFlow::with_share_bundle(ShareBundle::synthetic_from_adaptor_secret(
            &[0xC4; 32],
        ))
        .with_k(k);
        println!("mode={} k={k}", flow.name());

        let secp = Secp256k1::new();
        let signer = Keypair::new(&secp, &mut rand::thread_rng());
        let t0 = Instant::now();
        let pkg = flow
            .engine_create_assert(claim, "funding:txid:0", &signer)
            .expect("phase-c+ assert");
        println!(
            "garble+prove {:.1}s  H(L_invalid)={}",
            t0.elapsed().as_secs_f64(),
            hex::encode(pkg.h_l_invalid)
        );

        let t1 = Instant::now();
        let result = flow
            .challenger_evaluate(claim, &pkg.opening, &pkg.groth16, &pkg.h_l_invalid)
            .expect("phase-c+ evaluate");
        println!("evaluate {:.1}s", t1.elapsed().as_secs_f64());

        match result {
            EvaluationResult::Valid => {
                println!("Result: VALID – Engine can Timeout later");
                let _ = PhaseCPlusFlow::build_timeout("assert:0", "reserve:0", "engine");
            }
            EvaluationResult::Invalid { l_invalid } => {
                println!("Result: INVALID");
                println!("L_invalid: {}", hex::encode(l_invalid));
                let _ = PhaseCPlusFlow::build_disprove("assert:0", l_invalid, "slash");
                println!("Challenger can now broadcast Disprove");
            }
        }
        println!("\n=== Done ===");
    }
}
