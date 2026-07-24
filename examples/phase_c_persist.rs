//! Phase C ciphertext persistence smoke (`gsv`).
//!
//! Garble once to disk → verify Blake3-accum hash → Evaluate from store
//! (no re-garble). Cube-compatible: CT stays off-chain; Assert only needs
//! the commitment + opening + H(L*).
//!
//! ```bash
//! export CARGO_TARGET_DIR=./target
//! cargo run --example phase_c_persist --features gsv --no-default-features
//! ```

use std::env;

use beacon::{
    evaluate_and_from_store, garble_and_to_store, hashlock_commit, ClaimMini, CiphertextStore,
    DirectSeedOpening, EvaluationResult,
};

fn main() {
    println!("=== Beacon Phase C – ciphertext persistence ===\n");

    let dir = env::temp_dir().join(format!("beacon-persist-demo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = CiphertextStore::open(&dir).expect("store");
    println!("store={}", dir.display());

    let material = DirectSeedOpening::from_claim_bytes(0, b"persist-demo").derive_label_material();
    let pkg = garble_and_to_store(&store, 0, &material).expect("garble");
    println!(
        "wrote {} (hash={})",
        pkg.meta.stream_file,
        hex::encode(pkg.meta.ciphertext_hash)
    );
    store.verify(0).expect("verify");

    let mut claim = ClaimMini::make_valid(
        [1; 32],
        100_000,
        40_000,
        [10; 32],
        [11; 32],
        [12; 32],
        [13; 32],
    );
    match evaluate_and_from_store(&store, &claim, 0).expect("eval") {
        EvaluationResult::Valid => println!("honest → Valid (from disk)"),
        EvaluationResult::Invalid { .. } => panic!("expected Valid"),
    }

    claim.total_out = 250_000;
    match evaluate_and_from_store(&store, &claim, 0).expect("eval cheat") {
        EvaluationResult::Invalid { l_invalid } => {
            assert_eq!(hashlock_commit(&l_invalid), hashlock_commit(&pkg.meta.l_invalid));
            println!("cheat  → Invalid L*={} (from disk)", hex::encode(l_invalid));
        }
        EvaluationResult::Valid => panic!("expected Invalid"),
    }

    let _ = std::fs::remove_dir_all(&dir);
    println!("\nOK — CT persist + hash-check + evaluate-from-store works.");
}
