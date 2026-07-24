//! Beacon core — reference implementation of the assertion protocol.
//!
//! This crate contains **protocol** types and traits only.
//! No Bitcoin, networking, serialization, database, or proof-system code.
//!
//! Normative specification: `rfcs/0001-assertion-protocol.md` in this repository.
//!
//! Domain types (`Assertion`, `Challenge`, `Settlement`, …) land in subsequent
//! commits. This crate must remain compilable at every commit.

#![forbid(unsafe_code)]
