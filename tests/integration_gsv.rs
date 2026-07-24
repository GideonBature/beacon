//! Integration suite — GSV-linked Phase C (`gsv` feature).
//!
//! Covers AND garble persist / evaluate-from-store, cut-and-choose re-garble,
//! and linked `GarbledSnarkBackend`. Full Phase C+ Groth16 is `#[ignore]`
//! (minutes; enable with `--ignored` in release).
//!
//! ```bash
//! export CARGO_TARGET_DIR=./target
//! cargo test --test integration_gsv --features gsv --no-default-features
//! ```

mod common;

use beacon::{
    check_openings_from_store, commits_from_store, evaluate_and_from_store, fixed_schedule,
    garble_and_to_store, hashlock_commit, load_and_package, open_check_instances,
    require_eval_committed, serialize_claim, verify_check_regarble, AssertOpening,
    AssertWitnessV1, CiphertextStore, CutAndChooseParams, DirectSeedOpening, EvaluationResult,
    GarbledSnarkBackend, PhaseCPlusFlow,
};
use beacon::backend::CircuitBackend;
use beacon::opening::LabelOpening;
use common::{invalid_claim, temp_dir, valid_claim};

#[test]
fn gsv_backend_is_linked_and_hashlock_aligned() {
    assert!(GarbledSnarkBackend::is_linked());
    let backend = GarbledSnarkBackend;
    assert_eq!(backend.name(), "garbled-snark-verifier");

    let bad = invalid_claim();
    let opening = DirectSeedOpening::from_claim_bytes(0, &serialize_claim(&bad));
    let h = backend.commit_l_invalid(&bad);
    match backend.evaluate(&bad, &opening) {
        EvaluationResult::Invalid { l_invalid } => {
            assert_eq!(hashlock_commit(&l_invalid), h);
        }
        EvaluationResult::Valid => panic!("expected Invalid"),
    }
    assert!(matches!(
        backend.evaluate(&valid_claim(), &opening),
        EvaluationResult::Valid
    ));
}

#[test]
fn and_garble_persist_verify_and_evaluate_from_store() {
    let dir = temp_dir("gsv-persist");
    let store = CiphertextStore::open(&dir).unwrap();
    let material = DirectSeedOpening::from_claim_bytes(0, b"itest-persist").derive_label_material();

    let pkg = garble_and_to_store(&store, 0, &material).unwrap();
    assert_eq!(pkg.meta.instance_id, 0);
    assert_eq!(store.verify(0).unwrap().ciphertext_hash, pkg.meta.ciphertext_hash);

    let loaded = load_and_package(&store, 0).unwrap();
    assert_eq!(loaded.meta.ciphertext_hash, pkg.meta.ciphertext_hash);
    assert_eq!(loaded.input_wire_bytes, pkg.input_wire_bytes);

    match evaluate_and_from_store(&store, &valid_claim(), 0).unwrap() {
        EvaluationResult::Valid => {}
        EvaluationResult::Invalid { .. } => panic!("honest claim → Valid"),
    }
    match evaluate_and_from_store(&store, &invalid_claim(), 0).unwrap() {
        EvaluationResult::Invalid { l_invalid } => {
            assert_eq!(hashlock_commit(&l_invalid), hashlock_commit(&pkg.meta.l_invalid));
        }
        EvaluationResult::Valid => panic!("cheat → Invalid"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cut_and_choose_open_check_regarble_and_assert_witness() {
    let dir = temp_dir("gsv-cnc");
    let store = CiphertextStore::open(&dir).unwrap();
    let params = CutAndChooseParams {
        n: 3,
        eval_count: 1,
    };
    let schedule = fixed_schedule(params).unwrap();

    for i in 0..params.n {
        let material =
            DirectSeedOpening::from_claim_bytes(i, b"itest-cnc").derive_label_material();
        garble_and_to_store(&store, i, &material).unwrap();
    }

    let commits = commits_from_store(&store, params.n).unwrap();
    let openings = check_openings_from_store(&store, &schedule).unwrap();
    open_check_instances(&store, &schedule, &commits, &openings).unwrap();
    verify_check_regarble(&store, &openings).unwrap();

    let eval_meta = require_eval_committed(&store, &schedule, &commits).unwrap();
    let a = schedule.eval_instance;
    assert_eq!(eval_meta.instance_id, a);

    let mut claim = valid_claim();
    let claim_bytes = serialize_claim(&claim);
    let opening = AssertOpening::Direct(DirectSeedOpening::from_claim_bytes(a, &claim_bytes));
    let wit = AssertWitnessV1::new(
        claim_bytes,
        opening,
        hashlock_commit(&eval_meta.l_invalid),
        None,
    )
    .with_ciphertext_hash(eval_meta.ciphertext_hash);

    let recovered = AssertWitnessV1::decode(&wit.encode()).unwrap();
    assert_eq!(LabelOpening::instance_id(&recovered.opening), a);
    recovered
        .check_ciphertext_hash(&eval_meta.ciphertext_hash)
        .unwrap();

    match evaluate_and_from_store(&store, &claim, a).unwrap() {
        EvaluationResult::Valid => {}
        EvaluationResult::Invalid { .. } => panic!("expected Valid"),
    }
    claim.total_out = 250_000;
    assert!(matches!(
        evaluate_and_from_store(&store, &claim, a).unwrap(),
        EvaluationResult::Invalid { .. }
    ));

    // Tamper a check-set stream → re-garble verify fails
    let check_id = schedule.check_set[0];
    std::fs::write(store.stream_path(check_id), b"tampered-ct").unwrap();
    assert!(verify_check_regarble(&store, &openings).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Full garbled Groth16 (Default `k`). Slow; run manually:
/// `cargo test --test integration_gsv --features gsv --release -- --ignored --nocapture`
#[test]
#[ignore = "Phase C+ Groth16: minutes + high RAM; use --release -- --ignored"]
fn phase_c_plus_garbled_groth16_happy_and_cheat() {
    use secp256k1::{Keypair, Secp256k1};
    use rand::thread_rng;

    let flow = PhaseCPlusFlow::new().with_k(4);
    assert_eq!(flow.name(), "phase-c+/garbled-groth16");
    let secp = Secp256k1::new();
    let signer = Keypair::new(&secp, &mut thread_rng());

    let good = valid_claim();
    let pkg = flow
        .engine_create_assert(&good, "f:0", &signer)
        .expect("setup honest");
    let eval = flow
        .challenger_evaluate(&good, &pkg.opening, &pkg.groth16, &pkg.h_l_invalid)
        .expect("eval honest");
    assert!(matches!(eval, EvaluationResult::Valid));

    let bad = invalid_claim();
    let pkg = flow
        .engine_create_assert(&bad, "f:1", &signer)
        .expect("setup cheat");
    match flow
        .challenger_evaluate(&bad, &pkg.opening, &pkg.groth16, &pkg.h_l_invalid)
        .expect("eval cheat")
    {
        EvaluationResult::Invalid { l_invalid } => {
            assert_eq!(hashlock_commit(&l_invalid), pkg.h_l_invalid);
        }
        EvaluationResult::Valid => panic!("cheat must yield Invalid"),
    }
}
