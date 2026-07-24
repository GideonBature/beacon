//! Groth16 [`Verifiable`](beacon_core::Verifiable) adapter for Beacon.
//!
//! **Production path is verify-only:** applications (e.g. Cube) produce proofs;
//! this crate wraps proof + verifying key + public inputs so any
//! [`DisputeBackend`](beacon_core::DisputeBackend) can run [`Verifiable::check`]
//! without knowing `CubeVM`.
//!
//! [`testing`] helpers generate toy proofs for demos and unit tests. They are
//! not the Cube proving pipeline.

#![forbid(unsafe_code)]

mod evidence;
/// Toy circuit proving helpers (tests / examples only — not Cube's prover).
pub mod testing;

pub use evidence::{Groth16Evidence, Groth16Statement};
