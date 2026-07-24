//! Groth16 [`Verifiable`](beacon_core::Verifiable) adapter for Beacon.
//!
//! **Production path is verify-only:** applications (e.g. Cube) produce proofs;
//! this crate wraps proof + verifying key + public inputs so any
//! [`DisputeBackend`](beacon_core::DisputeBackend) can run [`Verifiable::check`]
//! without knowing `CubeVM`.
//!
//! Use [`VerifyingKeyRegistry`] to resolve circuit VKs by id when assembling
//! evidence. [`testing`] helpers generate toy proofs for demos and unit tests
//! only — not the Cube proving pipeline.

#![forbid(unsafe_code)]

mod evidence;
mod registry;
/// Toy circuit proving helpers (tests / examples only — not Cube's prover).
pub mod testing;

pub use evidence::{Groth16Evidence, Groth16Statement};
pub use registry::{RegistryError, VerifyingKeyId, VerifyingKeyRegistry};
