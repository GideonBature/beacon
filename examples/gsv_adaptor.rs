//! GSV-compatible adaptor opening smoke (`gsv-vsss`).
//!
//! ```bash
//! export CARGO_TARGET_DIR=./target
//! cargo run --example gsv_adaptor --features gsv-vsss --no-default-features
//! ```

use ark_ff::UniformRand;
use ark_secp256k1::Fr;
use beacon::{
    adaptor_share_from_gsv_fr_be, reconstruct_label_seed, AssertOpening, AssertWitnessV1,
    GsvAdaptorOpening, ShareBundle,
};
use rand::thread_rng;

fn main() {
    println!("=== Beacon GSV adaptor wire-compat ===\n");

    let mut rng = thread_rng();
    let evaluator = Fr::rand(&mut rng);
    let garbler = Fr::rand(&mut rng);
    let claim = b"cube-claim-public-inputs";

    let opening =
        GsvAdaptorOpening::create(2, claim, &evaluator, &garbler, &mut rng).expect("create");
    let fr_be = opening.extract_fr_be32().expect("extract");
    println!("instance={} Fr(BE)={}", opening.instance_id, hex::encode(fr_be));

    let share_le = adaptor_share_from_gsv_fr_be(&fr_be);
    let bundle = ShareBundle::synthetic_from_adaptor_secret(&share_le);
    let seed = reconstruct_label_seed(Some(&bundle), &share_le);
    println!("reconstruct_label_seed={}", hex::encode(seed));

    let wit = AssertWitnessV1::new(
        claim.to_vec(),
        AssertOpening::GsvAdaptor(opening.clone()),
        [0xAA; 32],
        Some(bundle),
    );
    let blob = wit.encode();
    let recovered = AssertWitnessV1::decode(&blob).expect("decode");
    match recovered.opening {
        AssertOpening::GsvAdaptor(o) => {
            assert_eq!(o.extract_fr().unwrap(), garbler);
            println!(
                "AssertWitnessV1 tag=3 round-trip OK ({} bytes)",
                blob.len()
            );
        }
        _ => panic!("expected GsvAdaptor"),
    }

    println!("\nOK — GSV Fr-share adaptor ≠ Phase B CubePhaseBLabels path.");
}
