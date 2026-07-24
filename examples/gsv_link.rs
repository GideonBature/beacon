//! Prove Beacon links `garbled-snark-verifier` and can execute a tiny circuit.
//!
//! ```bash
//! cargo run --example gsv_link
//! ```

use beacon::GarbledSnarkBackend;

fn main() {
    println!("=== Beacon ↔ garbled-snark-verifier link ===\n");
    println!("GarbledSnarkBackend::is_linked() = {}", GarbledSnarkBackend::is_linked());
    println!(
        "hardware_aes_available() = {}",
        garbled_snark_verifier::hardware_aes_available()
    );

    // Tiny Execute-mode circuit through the backend's linked path.
    let backend = GarbledSnarkBackend;
    println!("backend={}", backend.name());

    use beacon::{ClaimMini, CircuitBackend, DirectSeedOpening, EvaluationResult};
    let claim = ClaimMini::make_valid(
        [0x01; 32],
        100_000,
        40_000,
        [0x10; 32],
        [0x11; 32],
        [0x12; 32],
        [0x13; 32],
    );
    let opening = DirectSeedOpening::from_claim_bytes(0, &claim.preimage());
    let h = backend.commit_l_invalid(&claim);
    println!("H(L_invalid)={}", hex::encode(h));
    match backend.evaluate(&claim, &opening) {
        EvaluationResult::Valid => println!("evaluate(valid claim) = Valid"),
        EvaluationResult::Invalid { .. } => panic!("expected Valid"),
    }

    println!("\nOK — GSV crate is linked and callable.");
}
