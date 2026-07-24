//! Minimal cut-and-choose + Assert witness with ciphertext_hash (`gsv`).
//!
//! ```text
//! Setup:  garble n instances → CiphertextStore
//! Select: fixed/sample schedule → C, E={a}
//! Open:   verify check-set hashes
//! Assert: pack AssertWitnessV1(instance=a, ciphertext_hash)
//! Eval:   store verify vs witness → Evaluate-from-store
//! ```
//!
//! ```bash
//! export CARGO_TARGET_DIR=./target
//! cargo run --example phase_c_cnc --features gsv --no-default-features
//! ```

use std::env;

use beacon::{
    check_openings_from_store, commits_from_store, evaluate_and_from_store, fixed_schedule,
    garble_and_to_store, hashlock_commit, open_check_instances, require_eval_committed,
    AssertOpening, AssertWitnessV1, ClaimMini, CiphertextStore, CutAndChooseParams,
    DirectSeedOpening, EvaluationResult,
};

fn main() {
    println!("=== Beacon Phase C – cut-and-choose schedule ===\n");

    let dir = env::temp_dir().join(format!("beacon-cnc-demo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = CiphertextStore::open(&dir).expect("store");

    let params = CutAndChooseParams {
        n: 3,
        eval_count: 1,
    };
    let schedule = fixed_schedule(params).expect("schedule");
    println!(
        "schedule: n={} check={:?} eval={:?} a={}",
        schedule.n, schedule.check_set, schedule.eval_set, schedule.eval_instance
    );

    // Garble each instance with distinct label material (instance-bound seed).
    for i in 0..params.n {
        let material = DirectSeedOpening::from_claim_bytes(i, b"cnc-demo").derive_label_material();
        let pkg = garble_and_to_store(&store, i, &material).expect("garble");
        println!(
            "  gc_{i}.bin hash={}",
            hex::encode(pkg.meta.ciphertext_hash)
        );
    }

    let commits = commits_from_store(&store, params.n).expect("commits");
    let openings = check_openings_from_store(&store, &schedule).expect("openings");
    open_check_instances(&store, &schedule, &commits, &openings).expect("open C");
    let eval_meta = require_eval_committed(&store, &schedule, &commits).expect("eval commit");
    println!("check-set opened OK; eval a={} committed", eval_meta.instance_id);

    let a = schedule.eval_instance;
    let mut claim = ClaimMini::make_valid(
        [1; 32],
        100_000,
        40_000,
        [10; 32],
        [11; 32],
        [12; 32],
        [13; 32],
    );
    let claim_bytes = beacon::serialize_claim(&claim);
    let opening = AssertOpening::Direct(DirectSeedOpening::from_claim_bytes(a, &claim_bytes));
    let wit = AssertWitnessV1::new(
        claim_bytes,
        opening,
        hashlock_commit(&eval_meta.l_invalid),
        None,
    )
    .with_ciphertext_hash(eval_meta.ciphertext_hash);

    let blob = wit.encode();
    let recovered = AssertWitnessV1::decode(&blob).expect("decode");
    assert_eq!(recovered.statement.instance_id, a);
    recovered
        .check_ciphertext_hash(&eval_meta.ciphertext_hash)
        .expect("ct hash");
    println!(
        "AssertWitnessV1: instance={} ct_hash={} ({} bytes)",
        recovered.statement.instance_id,
        hex::encode(recovered.ciphertext_hash.unwrap()),
        blob.len()
    );

    match evaluate_and_from_store(&store, &claim, a).expect("eval") {
        EvaluationResult::Valid => println!("honest → Valid (instance a from disk)"),
        EvaluationResult::Invalid { .. } => panic!("expected Valid"),
    }

    claim.total_out = 250_000;
    match evaluate_and_from_store(&store, &claim, a).expect("eval cheat") {
        EvaluationResult::Invalid { l_invalid } => {
            println!("cheat  → Invalid L*={}", hex::encode(l_invalid));
        }
        EvaluationResult::Valid => panic!("expected Invalid"),
    }

    let _ = std::fs::remove_dir_all(&dir);
    println!("\nOK — C&C schedule + ciphertext_hash Assert + evaluate-from-store.");
}
