//! Integration suite — Beacon core (no `gsv` required).
//!
//! Covers Claim Mini, Phase A/B/C stand-in flows, AssertWitness, Taproot
//! builders, ciphertext store (sha256), and cut-and-choose schedule.
//!
//! ```bash
//! cargo test --test integration_core --no-default-features
//! ```

mod common;

use bitcoin::absolute;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use beacon::{
    attach_op_return_output, attach_to_funding_witness, build_assert_tx, build_disprove_tx,
    build_timeout_tx, check_openings_from_store, commits_from_store, deserialize_claim,
    extract_from_funding_witness, extract_from_op_return, fixed_schedule, hashlock_commit,
    open_check_instances, p2tr_address, require_eval_committed, sample_schedule, serialize_claim,
    sign_assert_keypath, validate_schedule, AssertOpening, AssertWitnessV1, CiphertextStore,
    ClaimMiniBackend, CutAndChooseParams, DirectSeedOpening, EvaluationResult, GarbledSnarkBackend,
    PhaseAFlow, PhaseBFlow, PhaseCFlow, ShareBundle, StoreError, WitnessError,
    REGTEST_DISPUTE_WINDOW,
};
use beacon::backend::CircuitBackend;
use beacon::opening::LabelOpening;
use beacon::phase_b::opening::AdaptorOpening;
use beacon::tx_templates::{AssertTemplate, DEFAULT_DISPUTE_WINDOW};
use common::{invalid_claim, temp_dir, valid_claim};
use rand::thread_rng;
use secp256k1::Secp256k1 as SecpLegacy;

// ---------------------------------------------------------------------------
// Claim Mini + backends
// ---------------------------------------------------------------------------

#[test]
fn claim_mini_valid_invalid_and_roots() {
    let good = valid_claim();
    assert!(good.verify());
    let bad = invalid_claim();
    assert!(!bad.verify());

    let mut wrong_root = good.clone();
    wrong_root.t1 = [0xFF; 32];
    assert!(!wrong_root.verify());
}

#[test]
fn backends_commit_and_evaluate_align_with_hashlock() {
    let backend = ClaimMiniBackend;
    assert_eq!(backend.name(), "claim-mini");
    let good = valid_claim();
    let bad = invalid_claim();
    let bytes = serialize_claim(&good);
    let opening = DirectSeedOpening::from_claim_bytes(0, &bytes);

    let h = backend.commit_l_invalid(&bad);
    match backend.evaluate(&bad, &opening) {
        EvaluationResult::Invalid { l_invalid } => {
            assert_eq!(hashlock_commit(&l_invalid), h);
        }
        EvaluationResult::Valid => panic!("expected invalid"),
    }
    assert!(matches!(
        backend.evaluate(&good, &opening),
        EvaluationResult::Valid
    ));

    let gsv = GarbledSnarkBackend;
    assert!(gsv.name().contains("garbled") || gsv.name().contains("gsv") || !gsv.name().is_empty());
    let h2 = gsv.commit_l_invalid(&bad);
    match gsv.evaluate(&bad, &opening) {
        EvaluationResult::Invalid { l_invalid } => {
            assert_eq!(hashlock_commit(&l_invalid), h2);
        }
        EvaluationResult::Valid => panic!("expected invalid"),
    }
}

// ---------------------------------------------------------------------------
// Phase A / B / C dispute flows (stand-in)
// ---------------------------------------------------------------------------

#[test]
fn phase_a_happy_timeout_and_unhappy_disprove() {
    let flow = PhaseAFlow::new(ClaimMiniBackend);
    assert_eq!(flow.backend().name(), "claim-mini");

    let good = valid_claim();
    let (tmpl, opening, h) = flow.engine_create_assert(&good, "txid:0");
    assert_eq!(tmpl.dispute_window, DEFAULT_DISPUTE_WINDOW);
    assert!(tmpl.connector_script_description().contains("Disprove"));
    assert!(matches!(
        flow.challenger_evaluate(&good, &opening, &h),
        EvaluationResult::Valid
    ));
    let timeout = PhaseAFlow::<ClaimMiniBackend>::build_timeout("a:0", "r:0", "pubkey");
    assert!(!timeout.assert_outpoint.is_empty());

    let bad = invalid_claim();
    let (tmpl, opening, h) = flow.engine_create_assert(&bad, "txid:1");
    match flow.challenger_evaluate(&bad, &opening, &h) {
        EvaluationResult::Invalid { l_invalid } => {
            assert_eq!(hashlock_commit(&l_invalid), h);
            assert_eq!(tmpl.hash_of_false_label, h);
            let d = PhaseAFlow::<ClaimMiniBackend>::build_disprove("a:0", l_invalid, "slash");
            assert!(!d.script_description().is_empty());
        }
        EvaluationResult::Valid => panic!("expected invalid"),
    }
}

#[test]
fn phase_b_adaptor_happy_and_unhappy() {
    let flow = PhaseBFlow::new(ClaimMiniBackend);
    let secp = SecpLegacy::new();
    let signer = secp256k1::Keypair::new(&secp, &mut thread_rng());

    let good = valid_claim();
    let (_t, opening, h) = flow
        .engine_create_assert(&good, "funding:0", &signer)
        .unwrap();
    assert!(matches!(
        flow.challenger_evaluate(&good, &opening, &h),
        EvaluationResult::Valid
    ));
    let material = opening.derive_label_material().unwrap();
    assert_ne!(material, [0u8; 32]);

    let bad = invalid_claim();
    let (_t, opening, h) = flow
        .engine_create_assert(&bad, "funding:1", &signer)
        .unwrap();
    match flow.challenger_evaluate(&bad, &opening, &h) {
        EvaluationResult::Invalid { l_invalid } => {
            assert_eq!(hashlock_commit(&l_invalid), h);
        }
        EvaluationResult::Valid => panic!("expected invalid"),
    }
}

#[test]
fn phase_c_stand_in_with_and_without_share_bundle() {
    let flow = PhaseCFlow::new();
    assert!(!flow.name().is_empty());
    let secp = SecpLegacy::new();
    let signer = secp256k1::Keypair::new(&secp, &mut thread_rng());

    let good = valid_claim();
    let (_t, opening, h) = flow
        .engine_create_assert(&good, "f:0", &signer)
        .unwrap();
    assert!(matches!(
        flow.challenger_evaluate(&good, &opening, &h),
        EvaluationResult::Valid
    ));

    let secret = [0x42u8; 32];
    let bundle = ShareBundle::synthetic_from_adaptor_secret(&secret);
    let flow = PhaseCFlow::with_share_bundle(bundle);
    let bad = invalid_claim();
    let (_t, opening, h) = flow
        .engine_create_assert(&bad, "f:1", &signer)
        .unwrap();
    match flow.challenger_evaluate(&bad, &opening, &h) {
        EvaluationResult::Invalid { l_invalid } => {
            assert_eq!(hashlock_commit(&l_invalid), h);
            let d = PhaseCFlow::build_disprove("a:0", l_invalid, "slash");
            assert_eq!(d.false_label, l_invalid);
            let t = PhaseCFlow::build_timeout("a:0", "r:0", "pk");
            assert_eq!(t.assert_outpoint, "a:0");
        }
        EvaluationResult::Valid => panic!("expected invalid"),
    }
}

#[test]
fn serialize_claim_roundtrip() {
    let c = valid_claim();
    let bytes = serialize_claim(&c);
    let back = deserialize_claim(&bytes).unwrap();
    assert_eq!(back.total_in, c.total_in);
    assert_eq!(back.total_out, c.total_out);
    assert_eq!(back.t1, c.t1);
    assert_eq!(back.h_new, c.h_new);
}

// ---------------------------------------------------------------------------
// AssertWitness + carriers
// ---------------------------------------------------------------------------

#[test]
fn assert_witness_direct_adaptor_errors_and_carriers() {
    let claim = valid_claim();
    let claim_bytes = serialize_claim(&claim);

    // Direct
    let opening = AssertOpening::Direct(DirectSeedOpening::from_claim_bytes(3, &claim_bytes));
    let h = [0x11; 32];
    let w = AssertWitnessV1::new(claim_bytes.clone(), opening, h, None).with_ciphertext_hash([0xAB; 32]);
    assert_eq!(w.statement.instance_id, 3);
    let enc = w.encode();
    let dec = AssertWitnessV1::decode(&enc).unwrap();
    dec.check_hashlock(&h).unwrap();
    dec.check_ciphertext_hash(&[0xAB; 32]).unwrap();
    assert!(matches!(
        dec.check_ciphertext_hash(&[0; 32]),
        Err(WitnessError::CiphertextHashMismatch)
    ));

    // Legacy without ct flag
    let mut legacy = AssertWitnessV1::new(
        claim_bytes.clone(),
        AssertOpening::Direct(DirectSeedOpening::from_claim_bytes(0, &claim_bytes)),
        h,
        None,
    )
    .encode();
    assert_eq!(legacy.pop(), Some(0));
    assert!(AssertWitnessV1::decode(&legacy).unwrap().ciphertext_hash.is_none());

    // Tampered claim
    let mut bad = AssertWitnessV1::new(
        claim_bytes.clone(),
        AssertOpening::Direct(DirectSeedOpening::from_claim_bytes(0, &claim_bytes)),
        h,
        None,
    );
    bad.claim_bytes[0] ^= 1;
    assert!(matches!(
        AssertWitnessV1::decode(&bad.encode()),
        Err(WitnessError::ClaimHashMismatch)
    ));

    // Bad magic
    assert!(matches!(
        AssertWitnessV1::decode(b"XXXX"),
        Err(WitnessError::BadMagic)
    ));

    // Adaptor + share bundle
    let (ao, _) = AdaptorOpening::create_ephemeral(1, &claim_bytes).unwrap();
    let bundle = ShareBundle::synthetic_from_adaptor_secret(&[9; 32]);
    let w = AssertWitnessV1::new(
        claim_bytes.clone(),
        AssertOpening::Adaptor(ao),
        h,
        Some(bundle),
    );
    let dec = AssertWitnessV1::decode(&w.encode()).unwrap();
    assert!(dec.share_bundle.is_some());
    assert!(matches!(dec.opening, AssertOpening::Adaptor(_)));

    // OP_RETURN carrier
    let blob = w.encode();
    let mut tx = bare_tx();
    attach_op_return_output(&mut tx, &blob).unwrap();
    assert_eq!(extract_from_op_return(&tx).unwrap(), blob);

    // Multi-push OP_RETURN
    let mut big = beacon::MAGIC.to_vec();
    big.extend(std::iter::repeat(0xCDu8).take(600));
    let mut tx2 = bare_tx();
    attach_op_return_output(&mut tx2, &big).unwrap();
    assert_eq!(extract_from_op_return(&tx2).unwrap(), big);

    // Annex carrier (research helper)
    let mut tx3 = bare_tx();
    tx3.input[0].witness.push([0u8; 64]); // fake sig
    attach_to_funding_witness(&mut tx3, &blob);
    assert_eq!(extract_from_funding_witness(&tx3).unwrap(), blob);
    assert!(extract_from_funding_witness(&bare_tx()).is_none());
}

fn bare_tx() -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

// ---------------------------------------------------------------------------
// Opening trait + instance binding
// ---------------------------------------------------------------------------

#[test]
fn openings_expose_label_opening_and_instance_binding() {
    let bytes = serialize_claim(&valid_claim());
    let d0 = DirectSeedOpening::from_claim_bytes(0, &bytes);
    let d1 = DirectSeedOpening::from_claim_bytes(1, &bytes);
    assert_ne!(d0.seed, d1.seed);
    assert_ne!(d0.derive_label_material(), d1.derive_label_material());
    assert_eq!(LabelOpening::instance_id(&d0), 0);
    assert_eq!(LabelOpening::public_inputs_hash(&d0), d0.public_inputs_hash);

    let a = AssertOpening::Direct(d0.clone());
    assert_eq!(a.version(), d0.version);
    assert_eq!(a.derive_label_material(), d0.derive_label_material());
}

// ---------------------------------------------------------------------------
// Ciphertext store + cut-and-choose schedule
// ---------------------------------------------------------------------------

#[test]
fn ciphertext_store_persist_verify_tamper_and_missing() {
    let dir = temp_dir("store");
    let store = CiphertextStore::open(&dir).unwrap();
    let meta = store
        .persist_bytes_sha256(5, b"stream-bytes", 99, 1, 0, [1; 32], [2; 32])
        .unwrap();
    assert_eq!(store.verify(5).unwrap(), meta);
    assert!(matches!(store.verify(99), Err(StoreError::NotFound(99))));

    std::fs::write(store.stream_path(5), b"tampered").unwrap();
    assert!(matches!(
        store.verify(5),
        Err(StoreError::HashMismatch { .. })
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cut_and_choose_schedule_sample_fixed_validate_open() {
    let params = CutAndChooseParams {
        n: 4,
        eval_count: 1,
    };
    let s = sample_schedule(&mut thread_rng(), params).unwrap();
    validate_schedule(&s, params).unwrap();
    assert_eq!(s.eval_set.len(), 1);
    assert_eq!(s.check_set.len(), 3);

    assert!(CutAndChooseParams { n: 0, eval_count: 1 }
        .validate()
        .is_err());
    assert!(CutAndChooseParams { n: 2, eval_count: 2 }
        .validate()
        .is_err());

    let fixed = fixed_schedule(CutAndChooseParams::default()).unwrap();
    assert_eq!(fixed.eval_instance, 2);

    let dir = temp_dir("cnc");
    let store = CiphertextStore::open(&dir).unwrap();
    for i in 0..3 {
        store
            .persist_bytes_sha256(i, &[i as u8; 8], 10 + i as u64, 1, 0, [3; 32], [4; 32])
            .unwrap();
    }
    let commits = commits_from_store(&store, 3).unwrap();
    let openings = check_openings_from_store(&store, &fixed).unwrap();
    open_check_instances(&store, &fixed, &commits, &openings).unwrap();
    let meta = require_eval_committed(&store, &fixed, &commits).unwrap();
    assert_eq!(meta.instance_id, fixed.eval_instance);

    // Opening eval instance as check must fail
    let mut bad_openings = openings.clone();
    bad_openings[0].instance_id = fixed.eval_instance;
    assert!(open_check_instances(&store, &fixed, &commits, &bad_openings).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Real Taproot Assert / Disprove / Timeout builders (offline)
// ---------------------------------------------------------------------------

#[test]
fn taproot_assert_disprove_timeout_builders() {
    let secp = Secp256k1::new();
    let engine = Keypair::new(&secp, &mut thread_rng());
    let funding = Keypair::new(&secp, &mut thread_rng());
    let change = p2tr_address(&funding, Network::Regtest);

    let l = [0xAB; 32];
    let h = hashlock_commit(&l);

    let mut assert_res = build_assert_tx(
        OutPoint::null(),
        Amount::from_sat(100_000),
        &engine,
        b"claim-bytes",
        h,
        Amount::from_sat(50_000),
        &change,
        REGTEST_DISPUTE_WINDOW,
        Amount::from_sat(500),
    )
    .unwrap();

    let funding_prev = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: p2tr_address(&funding, Network::Regtest).script_pubkey(),
    };

    let blob = AssertWitnessV1::new(
        b"claim-bytes".to_vec(),
        assert_res.opening.clone(),
        h,
        None,
    )
    .encode();
    attach_op_return_output(&mut assert_res.tx, &blob).unwrap();
    sign_assert_keypath(&mut assert_res.tx, &funding_prev, &funding).unwrap();
    assert_eq!(assert_res.tx.input[0].witness.len(), 1);
    assert_eq!(
        extract_from_op_return(&assert_res.tx).unwrap(),
        blob
    );

    let connector = assert_res.tx.output[assert_res.connector_vout as usize].clone();
    let disprove = build_disprove_tx(
        assert_res.tx.compute_txid(),
        assert_res.connector_vout,
        connector.value,
        l,
        h,
        &assert_res.taproot_spend_info,
        &p2tr_address(&funding, Network::Regtest),
        Amount::from_sat(500),
    )
    .unwrap();
    assert!(!disprove.input[0].witness.is_empty());

    let timeout = build_timeout_tx(
        assert_res.tx.compute_txid(),
        assert_res.connector_vout,
        &connector,
        &engine,
        &assert_res.taproot_spend_info,
        &p2tr_address(&engine, Network::Regtest),
        REGTEST_DISPUTE_WINDOW,
        Amount::from_sat(500),
    )
    .unwrap();
    assert_eq!(timeout.input[0].witness.nth(0).unwrap().len(), 64);
}

#[test]
fn taproot_assert_with_adaptor_opening_mode() {
    let secp = Secp256k1::new();
    let engine = Keypair::new(&secp, &mut thread_rng());
    let funding = Keypair::new(&secp, &mut thread_rng());
    let change = p2tr_address(&funding, Network::Regtest);
    let h = hashlock_commit(&[0xCD; 32]);

    let res = beacon::build_assert_tx_with_opening(
        OutPoint::null(),
        Amount::from_sat(100_000),
        &engine,
        b"adaptor-mode",
        h,
        Amount::from_sat(50_000),
        &change,
        REGTEST_DISPUTE_WINDOW,
        Amount::from_sat(500),
        beacon::OpeningMode::Adaptor,
    )
    .unwrap();
    assert!(matches!(res.opening, AssertOpening::Adaptor(_)));
    assert_eq!(res.h_l_invalid, h);
}

#[test]
fn phase_b_adaptor_secret_extract_roundtrip() {
    use beacon::phase_b::{complete_and_extract, create_adapted_signature, extract_adaptor_secret};
    use secp256k1::{Message, SecretKey};

    let secp = SecpLegacy::new();
    let signer = secp256k1::Keypair::new(&secp, &mut thread_rng());
    let t = SecretKey::new(&mut thread_rng());
    let msg = Message::from_digest([0x11u8; 32]);
    let adapted = create_adapted_signature(&signer, &msg, &t).unwrap();
    let recovered = complete_and_extract(&adapted).unwrap();
    assert_eq!(recovered, t);
    assert_eq!(
        extract_adaptor_secret(&adapted.adapted_s, &adapted.completed_s).unwrap(),
        t
    );
}

#[test]
fn assert_template_serde_and_descriptions() {
    let tmpl = AssertTemplate {
        funding_outpoint: "x:0".into(),
        claim: valid_claim(),
        hash_of_false_label: [9; 32],
        dispute_window: 10,
    };
    let json = serde_json::to_string(&tmpl).unwrap();
    let back: AssertTemplate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.dispute_window, 10);
    assert!(back.connector_script_description().contains("Timeout"));
}

// ---------------------------------------------------------------------------
// End-to-end: witness-bound Evaluate for A/B/C stand-in
// ---------------------------------------------------------------------------

#[test]
fn e2e_witness_bound_evaluate_phases_a_b_c() {
    let claim = invalid_claim();
    let claim_bytes = serialize_claim(&claim);

    // Phase A
    let flow_a = PhaseAFlow::new(ClaimMiniBackend);
    let (_t, o_a, h_a) = flow_a.engine_create_assert(&claim, "a:0");
    let wit_a = AssertWitnessV1::new(
        claim_bytes.clone(),
        AssertOpening::Direct(o_a),
        h_a,
        None,
    );
    let rec = AssertWitnessV1::decode(&wit_a.encode()).unwrap();
    let claim_r = deserialize_claim(&rec.claim_bytes).unwrap();
    match (&rec.opening, flow_a.challenger_evaluate(
        &claim_r,
        match &rec.opening {
            AssertOpening::Direct(o) => o,
            _ => unreachable!(),
        },
        &rec.statement.h_l_invalid,
    )) {
        (AssertOpening::Direct(_), EvaluationResult::Invalid { l_invalid }) => {
            assert_eq!(hashlock_commit(&l_invalid), h_a);
        }
        _ => panic!("phase a"),
    }

    // Phase B
    let flow_b = PhaseBFlow::new(ClaimMiniBackend);
    let secp = SecpLegacy::new();
    let signer = secp256k1::Keypair::new(&secp, &mut thread_rng());
    let (_t, o_b, h_b) = flow_b
        .engine_create_assert(&claim, "b:0", &signer)
        .unwrap();
    let wit_b = AssertWitnessV1::new(claim_bytes.clone(), AssertOpening::Adaptor(o_b), h_b, None);
    let rec = AssertWitnessV1::decode(&wit_b.encode()).unwrap();
    match &rec.opening {
        AssertOpening::Adaptor(o) => match flow_b.challenger_evaluate(&claim, o, &h_b) {
            EvaluationResult::Invalid { .. } => {}
            EvaluationResult::Valid => panic!("phase b"),
        },
        _ => panic!("expected adaptor"),
    }

    // Phase C
    let bundle = ShareBundle::synthetic_from_adaptor_secret(&[7; 32]);
    let flow_c = PhaseCFlow::with_share_bundle(bundle.clone());
    let (_t, o_c, h_c) = flow_c
        .engine_create_assert(&claim, "c:0", &signer)
        .unwrap();
    let wit_c = AssertWitnessV1::new(
        claim_bytes,
        AssertOpening::Adaptor(o_c),
        h_c,
        Some(bundle),
    )
    .with_ciphertext_hash([0xCE; 32]);
    let rec = AssertWitnessV1::decode(&wit_c.encode()).unwrap();
    assert_eq!(rec.ciphertext_hash, Some([0xCE; 32]));
    match &rec.opening {
        AssertOpening::Adaptor(o) => {
            let flow = PhaseCFlow::with_share_bundle(rec.share_bundle.clone().unwrap());
            assert!(matches!(
                flow.challenger_evaluate(&claim, o, &h_c),
                EvaluationResult::Invalid { .. }
            ));
        }
        _ => panic!("expected adaptor"),
    }
}
