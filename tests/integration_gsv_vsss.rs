//! Integration suite — GSV VSSS adaptor wire (`gsv-vsss` feature).
//!
//! Covers tag-3 `GsvAdaptorOpening`, Fr extract, ShareBundle reconstruct,
//! and AssertWitness round-trip.
//!
//! ```bash
//! export CARGO_TARGET_DIR=./target
//! cargo test --test integration_gsv_vsss --features gsv-vsss --no-default-features
//! ```

mod common;

use ark_ff::UniformRand;
use ark_secp256k1::Fr;
use beacon::{
    adaptor_share_from_gsv_fr_be, reconstruct_label_seed, serialize_claim, AssertOpening,
    AssertWitnessV1, GsvAdaptorOpening, ShareBundle, VERSION_GSV_ADAPTOR,
};
use beacon::opening::LabelOpening;
use common::valid_claim;
use rand::thread_rng;

#[test]
fn gsv_adaptor_create_extract_and_label_material() {
    let mut rng = thread_rng();
    let evaluator = Fr::rand(&mut rng);
    let garbler = Fr::rand(&mut rng);
    let claim_bytes = serialize_claim(&valid_claim());

    let opening =
        GsvAdaptorOpening::create(7, &claim_bytes, &evaluator, &garbler, &mut rng).unwrap();
    assert_eq!(opening.version, VERSION_GSV_ADAPTOR);
    assert_eq!(opening.instance_id, 7);
    assert_eq!(opening.extract_fr().unwrap(), garbler);

    let fr_be = opening.extract_fr_be32().unwrap();
    let fr_le = opening.extract_fr_le32().unwrap();
    assert_eq!(adaptor_share_from_gsv_fr_be(&fr_be), fr_le);

    let material = opening.derive_label_material().unwrap();
    assert_ne!(material, [0u8; 32]);
    assert_eq!(LabelOpening::instance_id(&opening), 7);
    assert_eq!(LabelOpening::derive_label_material(&opening), material);

    let (ephemeral, secret) =
        GsvAdaptorOpening::create_ephemeral(3, &claim_bytes, &evaluator, &mut rng).unwrap();
    assert_eq!(ephemeral.extract_fr().unwrap(), secret);
    assert_eq!(ephemeral.instance_id, 3);
}

#[test]
fn gsv_adaptor_share_bundle_reconstruct_path() {
    let mut rng = thread_rng();
    let evaluator = Fr::rand(&mut rng);
    let garbler = Fr::rand(&mut rng);
    let claim = b"reconstruct-path";

    let opening =
        GsvAdaptorOpening::create(2, claim, &evaluator, &garbler, &mut rng).unwrap();
    let fr_be = opening.extract_fr_be32().unwrap();
    let share_le = adaptor_share_from_gsv_fr_be(&fr_be);
    assert_eq!(share_le, opening.extract_fr_le32().unwrap());

    let bundle = ShareBundle::synthetic_from_adaptor_secret(&share_le);
    let seed = reconstruct_label_seed(Some(&bundle), &share_le);
    let seed_direct = reconstruct_label_seed(None, &share_le);
    // With synthetic bundle, reconstruct should still be deterministic / non-zero.
    assert_ne!(seed, [0u8; 32]);
    assert_ne!(seed_direct, [0u8; 32]);
}

#[test]
fn assert_witness_tag3_gsv_adaptor_roundtrip() {
    let mut rng = thread_rng();
    let evaluator = Fr::rand(&mut rng);
    let garbler = Fr::rand(&mut rng);
    let claim_bytes = serialize_claim(&valid_claim());

    let opening =
        GsvAdaptorOpening::create(2, &claim_bytes, &evaluator, &garbler, &mut rng).unwrap();
    let fr_be = opening.extract_fr_be32().unwrap();
    let share_le = adaptor_share_from_gsv_fr_be(&fr_be);
    let bundle = ShareBundle::synthetic_from_adaptor_secret(&share_le);

    let h = [0xAA; 32];
    let wit = AssertWitnessV1::new(
        claim_bytes,
        AssertOpening::GsvAdaptor(opening.clone()),
        h,
        Some(bundle),
    )
    .with_ciphertext_hash([0xCC; 32]);

    let recovered = AssertWitnessV1::decode(&wit.encode()).unwrap();
    recovered.check_hashlock(&h).unwrap();
    recovered.check_ciphertext_hash(&[0xCC; 32]).unwrap();
    assert!(recovered.share_bundle.is_some());

    match recovered.opening {
        AssertOpening::GsvAdaptor(o) => {
            assert_eq!(o.extract_fr().unwrap(), garbler);
            assert_eq!(o.instance_id, 2);
            assert_eq!(o.version, VERSION_GSV_ADAPTOR);
            assert_eq!(
                o.derive_label_material().unwrap(),
                opening.derive_label_material().unwrap()
            );
        }
        _ => panic!("expected GsvAdaptor (tag 3)"),
    }
}

#[test]
fn gsv_adaptor_encode_fields_roundtrip() {
    let mut rng = thread_rng();
    let evaluator = Fr::rand(&mut rng);
    let garbler = Fr::rand(&mut rng);
    let o = GsvAdaptorOpening::create(9, b"fields", &evaluator, &garbler, &mut rng).unwrap();
    let enc = o.encode_fields();
    let dec = GsvAdaptorOpening::decode_fields(&enc).unwrap();
    assert_eq!(dec, o);
    assert_eq!(dec.extract_fr().unwrap(), garbler);
}
