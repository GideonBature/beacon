//! Extractable Assert openings (Phase A direct seed, Phase B adaptor).

use crate::phase_a::opening::DirectSeedOpening;
use crate::phase_b::opening::AdaptorOpening;

/// Common interface for recovering label material from an Assert opening.
pub trait LabelOpening {
    fn version(&self) -> u8;
    fn instance_id(&self) -> u32;
    fn public_inputs_hash(&self) -> [u8; 32];
    /// Deterministic stand-in for wide-label material of the opened instance.
    fn derive_label_material(&self) -> [u8; 32];
}

impl LabelOpening for DirectSeedOpening {
    fn version(&self) -> u8 {
        self.version
    }

    fn instance_id(&self) -> u32 {
        self.instance_id
    }

    fn public_inputs_hash(&self) -> [u8; 32] {
        self.public_inputs_hash
    }

    fn derive_label_material(&self) -> [u8; 32] {
        DirectSeedOpening::derive_label_material(self)
    }
}

impl LabelOpening for AdaptorOpening {
    fn version(&self) -> u8 {
        self.version
    }

    fn instance_id(&self) -> u32 {
        self.instance_id
    }

    fn public_inputs_hash(&self) -> [u8; 32] {
        self.public_inputs_hash
    }

    fn derive_label_material(&self) -> [u8; 32] {
        AdaptorOpening::derive_label_material(self)
            .expect("adaptor opening must extract cleanly")
    }
}

/// Opening carried alongside an Assert (witness interpretation).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum AssertOpening {
    Direct(DirectSeedOpening),
    Adaptor(AdaptorOpening),
}

impl AssertOpening {
    pub fn as_label_opening(&self) -> &dyn LabelOpening {
        match self {
            Self::Direct(o) => o,
            Self::Adaptor(o) => o,
        }
    }
}

impl LabelOpening for AssertOpening {
    fn version(&self) -> u8 {
        self.as_label_opening().version()
    }

    fn instance_id(&self) -> u32 {
        self.as_label_opening().instance_id()
    }

    fn public_inputs_hash(&self) -> [u8; 32] {
        self.as_label_opening().public_inputs_hash()
    }

    fn derive_label_material(&self) -> [u8; 32] {
        self.as_label_opening().derive_label_material()
    }
}
