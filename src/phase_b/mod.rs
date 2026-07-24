//! Phase B – Schnorr adaptor extractable opening.
//!
//! Replaces the Phase A direct seed with an adaptor-signature offset.
//! Taproot connector / Disprove / Timeout stay unchanged.
//!
//! With `gsv-vsss`: [`gsv_adaptor`] provides GSV `AdaptorInfo`-compatible
//! Fr-share openings (Assert witness tag 3).

pub mod adaptor;
pub mod flow;
pub mod opening;

#[cfg(feature = "gsv-vsss")]
pub mod gsv_adaptor;

pub use adaptor::{complete_and_extract, create_adapted_signature, extract_adaptor_secret};
pub use flow::PhaseBFlow;
pub use opening::AdaptorOpening;

#[cfg(feature = "gsv-vsss")]
pub use gsv_adaptor::{GsvAdaptorOpening, VERSION_GSV_ADAPTOR};
