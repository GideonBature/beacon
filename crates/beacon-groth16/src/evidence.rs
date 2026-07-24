//! Groth16 evidence that implements Beacon's [`Verifiable`] boundary.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_snark::SNARK;
use beacon_core::Verifiable;

/// Public inputs for a Groth16 verification (the Beacon statement).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16Statement {
    /// Public inputs in circuit order.
    pub public_inputs: Vec<Fr>,
}

impl Groth16Statement {
    /// Create a statement from public inputs.
    #[must_use]
    pub fn new(public_inputs: Vec<Fr>) -> Self {
        Self { public_inputs }
    }

    /// Borrow public inputs.
    #[must_use]
    pub fn public_inputs(&self) -> &[Fr] {
        &self.public_inputs
    }
}

/// Groth16 proof evidence over BN254.
///
/// Applications (e.g. Cube) produce the proof; Beacon only verifies via
/// [`Verifiable::check`]. The verifying key is carried with the evidence for
/// the thin adapter; a later revision may resolve VKs from a registry by id.
#[derive(Clone, Debug)]
pub struct Groth16Evidence {
    statement: Groth16Statement,
    proof: Proof<Bn254>,
    vk: VerifyingKey<Bn254>,
}

impl Groth16Evidence {
    /// Assemble evidence from statement, proof, and verifying key.
    #[must_use]
    pub fn new(statement: Groth16Statement, proof: Proof<Bn254>, vk: VerifyingKey<Bn254>) -> Self {
        Self {
            statement,
            proof,
            vk,
        }
    }

    /// Borrow the Groth16 proof.
    #[must_use]
    pub const fn proof(&self) -> &Proof<Bn254> {
        &self.proof
    }

    /// Borrow the verifying key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey<Bn254> {
        &self.vk
    }
}

impl Verifiable for Groth16Evidence {
    type Statement = Groth16Statement;

    fn statement(&self) -> &Self::Statement {
        &self.statement
    }

    fn check(&self) -> bool {
        Groth16::<Bn254>::verify(&self.vk, &self.statement.public_inputs, &self.proof)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{prove_product, ProductWitness};

    #[test]
    fn valid_product_proof_checks() {
        let (evidence, _) = prove_product(ProductWitness { a: 3, b: 5 });
        assert!(evidence.check());
        assert_eq!(evidence.statement().public_inputs.len(), 1);
    }

    #[test]
    fn wrong_public_input_fails_check() {
        let (evidence, product) = prove_product(ProductWitness { a: 3, b: 5 });
        let bad = crate::testing::with_public_inputs(&evidence, vec![product + Fr::from(1u64)]);
        assert!(!bad.check());
    }
}
