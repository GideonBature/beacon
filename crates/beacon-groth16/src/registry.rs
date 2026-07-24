//! Verifying-key registry for Groth16 evidence construction.
//!
//! Applications (e.g. Cube) typically hold circuit VKs out-of-band. The registry
//! lets them resolve a [`VerifyingKeyId`] when assembling [`Groth16Evidence`].
//! Resolved evidence remains self-contained so [`Verifiable::check`] needs no
//! ambient context (`MockBackend` stays unchanged).

use std::collections::HashMap;
use std::fmt;

use ark_bn254::Bn254;
use ark_groth16::{Proof, VerifyingKey};

use crate::{Groth16Evidence, Groth16Statement};

/// Stable identifier for a registered verifying key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VerifyingKeyId(String);

impl VerifyingKeyId {
    /// Create a verifying-key id.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the raw id string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VerifyingKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&str> for VerifyingKeyId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for VerifyingKeyId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Errors from registry lookup / evidence assembly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// No verifying key registered under this id.
    UnknownVerifyingKey(VerifyingKeyId),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVerifyingKey(id) => write!(f, "unknown verifying key id: {id}"),
        }
    }
}

impl std::error::Error for RegistryError {}

/// In-memory map of verifying keys keyed by [`VerifyingKeyId`].
#[derive(Clone, Debug, Default)]
pub struct VerifyingKeyRegistry {
    keys: HashMap<VerifyingKeyId, VerifyingKey<Bn254>>,
}

impl VerifyingKeyRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) a verifying key under `id`.
    pub fn register(&mut self, id: impl Into<VerifyingKeyId>, vk: VerifyingKey<Bn254>) {
        self.keys.insert(id.into(), vk);
    }

    /// Returns `true` if `id` is registered.
    #[must_use]
    pub fn contains(&self, id: &VerifyingKeyId) -> bool {
        self.keys.contains_key(id)
    }

    /// Borrow a registered verifying key.
    #[must_use]
    pub fn get(&self, id: &VerifyingKeyId) -> Option<&VerifyingKey<Bn254>> {
        self.keys.get(id)
    }

    /// Number of registered keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns `true` if no keys are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Build self-contained evidence by resolving `vk_id` from this registry.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::UnknownVerifyingKey`] if `vk_id` is missing.
    pub fn evidence(
        &self,
        vk_id: impl Into<VerifyingKeyId>,
        statement: Groth16Statement,
        proof: Proof<Bn254>,
    ) -> Result<Groth16Evidence, RegistryError> {
        let vk_id = vk_id.into();
        let vk = self
            .keys
            .get(&vk_id)
            .cloned()
            .ok_or_else(|| RegistryError::UnknownVerifyingKey(vk_id.clone()))?;
        Ok(Groth16Evidence::with_vk_id(statement, proof, vk, vk_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{prove_product_parts, ProductWitness};
    use beacon_core::Verifiable;

    #[test]
    fn registry_builds_verifiable_evidence() {
        let (vk, proof, product) = prove_product_parts(ProductWitness { a: 3, b: 5 });
        let mut registry = VerifyingKeyRegistry::new();
        let id = VerifyingKeyId::new("toy-product-v1");
        registry.register(id.clone(), vk);

        let evidence = registry
            .evidence(id.clone(), Groth16Statement::new(vec![product]), proof)
            .unwrap();
        assert!(evidence.check());
        assert_eq!(evidence.vk_id(), Some(&id));
    }

    #[test]
    fn unknown_id_errors() {
        let registry = VerifyingKeyRegistry::new();
        let err = registry
            .evidence(
                "missing",
                Groth16Statement::new(vec![]),
                // dummy won't be reached — need a real proof type; use parts
                {
                    let (vk, proof, _) = prove_product_parts(ProductWitness { a: 1, b: 1 });
                    let _ = vk;
                    proof
                },
            )
            .unwrap_err();
        assert!(matches!(err, RegistryError::UnknownVerifyingKey(_)));
    }
}
