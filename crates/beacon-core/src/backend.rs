//! Dispute backend interface (trait lands with `MockBackend`).
//!
//! This module currently re-exports [`BackendId`] so callers can name backends
//! without depending on a concrete implementation. The `DisputeBackend` trait
//! will be added when the in-memory mock engine is implemented.

pub use crate::id::BackendId;
