//! Test/example helpers that **generate** Groth16 proofs for a toy circuit.
//!
//! Cube (or another application) owns real proving. These helpers exist so
//! Beacon can integration-test the Groth16 [`Verifiable`](beacon_core::Verifiable)
//! adapter without depending on Cube.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use crate::{Groth16Evidence, Groth16Statement};

/// Private witness for the toy product circuit: public `c = a * b`.
#[derive(Clone, Copy, Debug)]
pub struct ProductWitness {
    /// First factor.
    pub a: u64,
    /// Second factor.
    pub b: u64,
}

#[derive(Clone)]
struct ProductCircuit {
    a: Option<Fr>,
    b: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for ProductCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            a *= &b;
            Ok(a)
        })?;

        cs.enforce_r1cs_constraint(
            || ark_relations::lc!() + a,
            || ark_relations::lc!() + b,
            || ark_relations::lc!() + c,
        )?;
        Ok(())
    }
}

fn setup_and_prove(witness: ProductWitness) -> (VerifyingKey<Bn254>, Proof<Bn254>, Fr) {
    let mut rng = StdRng::seed_from_u64(42);
    let a = Fr::from(witness.a);
    let b = Fr::from(witness.b);
    let mut c = a;
    c *= &b;

    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(ProductCircuit { a: None, b: None }, &mut rng)
            .expect("groth16 setup");

    let proof = Groth16::<Bn254>::prove(
        &pk,
        ProductCircuit {
            a: Some(a),
            b: Some(b),
        },
        &mut rng,
    )
    .expect("groth16 prove");

    (vk, proof, c)
}

/// Setup + prove a product instance. Returns evidence and the public product.
#[must_use]
pub fn prove_product(witness: ProductWitness) -> (Groth16Evidence, Fr) {
    let (vk, proof, c) = setup_and_prove(witness);
    let evidence = Groth16Evidence::new(Groth16Statement::new(vec![c]), proof, vk);
    (evidence, c)
}

/// Like [`prove_product`], but returns VK / proof / public input separately
/// so callers can exercise [`crate::VerifyingKeyRegistry`].
#[must_use]
pub fn prove_product_parts(witness: ProductWitness) -> (VerifyingKey<Bn254>, Proof<Bn254>, Fr) {
    setup_and_prove(witness)
}

/// Rebuild evidence with altered public inputs (for negative tests).
#[must_use]
pub fn with_public_inputs(evidence: &Groth16Evidence, public_inputs: Vec<Fr>) -> Groth16Evidence {
    match evidence.vk_id().cloned() {
        Some(id) => Groth16Evidence::with_vk_id(
            Groth16Statement::new(public_inputs),
            evidence.proof().clone(),
            evidence.verifying_key().clone(),
            id,
        ),
        None => Groth16Evidence::new(
            Groth16Statement::new(public_inputs),
            evidence.proof().clone(),
            evidence.verifying_key().clone(),
        ),
    }
}
