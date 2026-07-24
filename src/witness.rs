//! Versioned Assert witness packing (Cube / BitVM3-compatible).
//!
//! Matches the logical layout in `docs/10-assert-witness-and-tapscript.md`:
//! public statement + extractable opening (+ optional share bundle).
//!
//! The connector Taproot still only enforces `H(L*)` / Timeout. The packed
//! witness is published so any challenger who sees the Assert can Evaluate
//! without out-of-band state. Default carrier: chunked `OP_RETURN` output
//! (schema independent of carrier; see docs).

use crate::opening::{AssertOpening, LabelOpening};
use crate::phase_a::opening::DirectSeedOpening;
use crate::phase_b::opening::AdaptorOpening;
use crate::phase_c::reconstruct::ShareBundle;
use sha2::{Digest, Sha256};

#[cfg(feature = "gsv-vsss")]
use crate::phase_b::gsv_adaptor::GsvAdaptorOpening;

/// Magic prefix: Beacon Assert Compact.
pub const MAGIC: &[u8; 4] = b"BEAC";
/// Wire format version of this packing (not Phase A/B opening version).
pub const FORMAT_V1: u8 = 1;

const OPENING_DIRECT: u8 = 1;
const OPENING_ADAPTOR: u8 = 2;
#[cfg(feature = "gsv-vsss")]
const OPENING_GSV_ADAPTOR: u8 = 3;

/// Public statement always visible with the Assert (Cube whitepaper: asserted claim).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicStatement {
    /// Opening protocol: 1 = direct seed, 2 = adaptor (matches opening versions).
    pub protocol_version: u8,
    /// Evaluation instance `a` (VSSS / cut-and-choose).
    pub instance_id: u32,
    /// `SHA256(claim_bytes)` — binds the public statement.
    pub public_inputs_hash: [u8; 32],
    /// Optional Cube state-transition id; `SHA256(claim_bytes)` when unset.
    pub claim_id: [u8; 32],
    /// Disprove hashlock commitment `H(L*)` (must match connector leaf).
    pub h_l_invalid: [u8; 32],
}

/// Packed Assert witness: statement + extractable opening + optional VSSS check-set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertWitnessV1 {
    pub statement: PublicStatement,
    /// Cleartext public claim / public inputs (Claim Mini now; Cube Groth16 publics later).
    pub claim_bytes: Vec<u8>,
    pub opening: AssertOpening,
    pub share_bundle: Option<ShareBundle>,
    /// Off-chain garbled CT commitment for `statement.instance_id` (eval instance `a`).
    pub ciphertext_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessError {
    BadMagic,
    BadFormat,
    Truncated,
    BadOpeningTag(u8),
    OpeningMismatch,
    ClaimHashMismatch,
    HashlockMismatch,
    CiphertextHashMismatch,
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "assert witness: bad magic"),
            Self::BadFormat => write!(f, "assert witness: unsupported format"),
            Self::Truncated => write!(f, "assert witness: truncated"),
            Self::BadOpeningTag(t) => write!(f, "assert witness: bad opening tag {t}"),
            Self::OpeningMismatch => write!(f, "assert witness: opening does not match statement"),
            Self::ClaimHashMismatch => write!(f, "assert witness: claim_bytes hash mismatch"),
            Self::HashlockMismatch => {
                write!(f, "assert witness: h_l_invalid does not match connector")
            }
            Self::CiphertextHashMismatch => {
                write!(f, "assert witness: ciphertext_hash does not match store")
            }
        }
    }
}

impl std::error::Error for WitnessError {}

impl AssertWitnessV1 {
    /// Build a packed witness from Assert construction results.
    pub fn new(
        claim_bytes: Vec<u8>,
        opening: AssertOpening,
        h_l_invalid: [u8; 32],
        share_bundle: Option<ShareBundle>,
    ) -> Self {
        let public_inputs_hash = sha256(&claim_bytes);
        let claim_id = public_inputs_hash;
        let protocol_version = LabelOpening::version(&opening);
        let instance_id = LabelOpening::instance_id(&opening);
        Self {
            statement: PublicStatement {
                protocol_version,
                instance_id,
                public_inputs_hash,
                claim_id,
                h_l_invalid,
            },
            claim_bytes,
            opening,
            share_bundle,
            ciphertext_hash: None,
        }
    }

    /// Bind the off-chain CT commitment for the evaluation instance.
    pub fn with_ciphertext_hash(mut self, hash: [u8; 32]) -> Self {
        self.ciphertext_hash = Some(hash);
        self
    }

    /// Encode to bytes (`MAGIC || FORMAT || …`).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_V1);
        out.push(self.statement.protocol_version);
        out.extend_from_slice(&self.statement.instance_id.to_le_bytes());
        out.extend_from_slice(&self.statement.public_inputs_hash);
        out.extend_from_slice(&self.statement.claim_id);
        out.extend_from_slice(&self.statement.h_l_invalid);
        write_bytes(&mut out, &self.claim_bytes);
        match &self.opening {
            AssertOpening::Direct(o) => {
                out.push(OPENING_DIRECT);
                out.push(o.version);
                out.extend_from_slice(&o.instance_id.to_le_bytes());
                out.extend_from_slice(&o.seed);
                out.extend_from_slice(&o.public_inputs_hash);
            }
            AssertOpening::Adaptor(o) => {
                out.push(OPENING_ADAPTOR);
                out.push(o.version);
                out.extend_from_slice(&o.instance_id.to_le_bytes());
                out.extend_from_slice(&o.signer_xonly);
                out.extend_from_slice(&o.adaptor_point);
                out.extend_from_slice(&o.nonce_x);
                out.extend_from_slice(&o.adapted_s);
                out.extend_from_slice(&o.completed_s);
                out.extend_from_slice(&o.message);
                out.extend_from_slice(&o.public_inputs_hash);
            }
            #[cfg(feature = "gsv-vsss")]
            AssertOpening::GsvAdaptor(o) => {
                out.push(OPENING_GSV_ADAPTOR);
                out.extend_from_slice(&o.encode_fields());
            }
        }
        match &self.share_bundle {
            None => out.push(0),
            Some(b) => {
                out.push(1);
                encode_share_bundle(&mut out, b);
            }
        }
        match &self.ciphertext_hash {
            None => out.push(0),
            Some(h) => {
                out.push(1);
                out.extend_from_slice(h);
            }
        }
        out
    }

    /// Decode and check internal consistency (claim hash ↔ statement).
    pub fn decode(bytes: &[u8]) -> Result<Self, WitnessError> {
        let mut c = Cursor::new(bytes);
        let magic = c.read_exact(4)?;
        if magic != MAGIC {
            return Err(WitnessError::BadMagic);
        }
        if c.read_u8()? != FORMAT_V1 {
            return Err(WitnessError::BadFormat);
        }
        let protocol_version = c.read_u8()?;
        let instance_id = c.read_u32()?;
        let public_inputs_hash = c.read_array32()?;
        let claim_id = c.read_array32()?;
        let h_l_invalid = c.read_array32()?;
        let claim_bytes = c.read_bytes()?;
        if sha256(&claim_bytes) != public_inputs_hash {
            return Err(WitnessError::ClaimHashMismatch);
        }
        let opening = match c.read_u8()? {
            OPENING_DIRECT => {
                let version = c.read_u8()?;
                let oid = c.read_u32()?;
                let seed = c.read_array32()?;
                let pih = c.read_array32()?;
                AssertOpening::Direct(DirectSeedOpening {
                    version,
                    instance_id: oid,
                    seed,
                    public_inputs_hash: pih,
                })
            }
            OPENING_ADAPTOR => {
                let version = c.read_u8()?;
                let oid = c.read_u32()?;
                AssertOpening::Adaptor(AdaptorOpening {
                    version,
                    instance_id: oid,
                    signer_xonly: c.read_array32()?,
                    adaptor_point: c.read_array32()?,
                    nonce_x: c.read_array32()?,
                    adapted_s: c.read_array32()?,
                    completed_s: c.read_array32()?,
                    message: c.read_array32()?,
                    public_inputs_hash: c.read_array32()?,
                })
            }
            #[cfg(feature = "gsv-vsss")]
            OPENING_GSV_ADAPTOR => {
                // Remaining opening fields until share_flag: version..completed_sig.
                // Layout size is fixed — read exact field blob.
                const GSV_FIELDS_LEN: usize = 1 + 4 + 32 + 32 + 32 + 33 + 33 + 32 + 64;
                let fields = c.read_exact(GSV_FIELDS_LEN)?;
                let o = GsvAdaptorOpening::decode_fields(fields)
                    .map_err(|_| WitnessError::BadFormat)?;
                AssertOpening::GsvAdaptor(o)
            }
            t => return Err(WitnessError::BadOpeningTag(t)),
        };
        let share_bundle = match c.read_u8()? {
            0 => None,
            1 => Some(decode_share_bundle(&mut c)?),
            _ => return Err(WitnessError::BadFormat),
        };
        // Optional trailing field (absent in early FORMAT_V1 blobs).
        let ciphertext_hash = if c.is_empty() {
            None
        } else {
            match c.read_u8()? {
                0 => None,
                1 => Some(c.read_array32()?),
                _ => return Err(WitnessError::BadFormat),
            }
        };
        if !c.is_empty() {
            return Err(WitnessError::BadFormat);
        }

        let wit = Self {
            statement: PublicStatement {
                protocol_version,
                instance_id,
                public_inputs_hash,
                claim_id,
                h_l_invalid,
            },
            claim_bytes,
            opening,
            share_bundle,
            ciphertext_hash,
        };
        wit.validate_opening()?;
        Ok(wit)
    }

    fn validate_opening(&self) -> Result<(), WitnessError> {
        if LabelOpening::version(&self.opening) != self.statement.protocol_version
            || LabelOpening::instance_id(&self.opening) != self.statement.instance_id
            || LabelOpening::public_inputs_hash(&self.opening) != self.statement.public_inputs_hash
        {
            return Err(WitnessError::OpeningMismatch);
        }
        Ok(())
    }

    /// Ensure packed `h_l_invalid` matches the connector commitment used on-chain.
    pub fn check_hashlock(&self, connector_h: &[u8; 32]) -> Result<(), WitnessError> {
        if &self.statement.h_l_invalid != connector_h {
            return Err(WitnessError::HashlockMismatch);
        }
        Ok(())
    }

    /// Ensure packed `ciphertext_hash` matches the store commitment for instance `a`.
    pub fn check_ciphertext_hash(&self, store_hash: &[u8; 32]) -> Result<(), WitnessError> {
        match &self.ciphertext_hash {
            None => Ok(()),
            Some(h) if h == store_hash => Ok(()),
            Some(_) => Err(WitnessError::CiphertextHashMismatch),
        }
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn write_bytes(out: &mut Vec<u8>, data: &[u8]) {
    let len = u32::try_from(data.len()).expect("claim too large");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
}

fn encode_share_bundle(out: &mut Vec<u8>, b: &ShareBundle) {
    out.extend_from_slice(&b.n.to_le_bytes());
    out.extend_from_slice(&b.threshold.to_le_bytes());
    out.extend_from_slice(&b.adaptor_index.to_le_bytes());
    let n = u32::try_from(b.check_shares.len()).expect("too many shares");
    out.extend_from_slice(&n.to_le_bytes());
    for (i, s) in &b.check_shares {
        out.extend_from_slice(&i.to_le_bytes());
        out.extend_from_slice(s);
    }
}

fn decode_share_bundle(c: &mut Cursor<'_>) -> Result<ShareBundle, WitnessError> {
    let n = c.read_u32()?;
    let threshold = c.read_u32()?;
    let adaptor_index = c.read_u32()?;
    let count = c.read_u32()? as usize;
    let mut check_shares = Vec::with_capacity(count);
    for _ in 0..count {
        check_shares.push((c.read_u32()?, c.read_array32()?));
    }
    Ok(ShareBundle {
        n,
        threshold,
        check_shares,
        adaptor_index,
    })
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8], WitnessError> {
        if self.pos + n > self.buf.len() {
            return Err(WitnessError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_u8(&mut self) -> Result<u8, WitnessError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, WitnessError> {
        let b = self.read_exact(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_array32(&mut self) -> Result<[u8; 32], WitnessError> {
        let b = self.read_exact(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, WitnessError> {
        let len = self.read_u32()? as usize;
        Ok(self.read_exact(len)?.to_vec())
    }
}

/// Build an `OP_RETURN` script carrying `blob` (chunked into ≤520-byte pushes).
pub fn op_return_script(blob: &[u8]) -> Result<bitcoin::ScriptBuf, WitnessError> {
    use bitcoin::script::{Builder, PushBytesBuf};
    let mut b = Builder::new().push_opcode(bitcoin::opcodes::all::OP_RETURN);
    for chunk in blob.chunks(520) {
        let push = PushBytesBuf::try_from(chunk.to_vec()).map_err(|_| WitnessError::BadFormat)?;
        b = b.push_slice(push);
    }
    Ok(b.into_script())
}

/// Append a 0-value OP_RETURN output with the packed Assert witness.
///
/// Call **before** signing (outputs enter the sighash). Prefer this carrier for
/// regtest; raise `-datacarriersize` above the blob size (see docker-compose).
pub fn attach_op_return_output(
    tx: &mut bitcoin::Transaction,
    blob: &[u8],
) -> Result<(), WitnessError> {
    tx.output.push(bitcoin::TxOut {
        value: bitcoin::Amount::ZERO,
        script_pubkey: op_return_script(blob)?,
    });
    Ok(())
}

/// Recover packed Assert witness from the first OP_RETURN whose data starts with [`MAGIC`].
pub fn extract_from_op_return(tx: &bitcoin::Transaction) -> Option<Vec<u8>> {
    for out in &tx.output {
        let script = out.script_pubkey.as_bytes();
        if script.first() != Some(&0x6a) {
            continue; // not OP_RETURN
        }
        let mut data = Vec::new();
        let mut i = 1usize;
        while i < script.len() {
            let tag = script[i];
            i += 1;
            let len = if tag <= 75 {
                tag as usize
            } else if tag == 0x4c && i < script.len() {
                let l = script[i] as usize;
                i += 1;
                l
            } else if tag == 0x4d && i + 1 < script.len() {
                let l = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                l
            } else {
                return None;
            };
            if i + len > script.len() {
                return None;
            }
            data.extend_from_slice(&script[i..i + len]);
            i += len;
        }
        if data.get(..4) == Some(MAGIC.as_slice()) {
            return Some(data);
        }
    }
    None
}

/// Research helper: Taproot annex carrier (`0x50 || blob`). Non-standard on Bitcoin Core.
pub fn attach_to_funding_witness(tx: &mut bitcoin::Transaction, blob: &[u8]) {
    let mut annex = Vec::with_capacity(1 + blob.len());
    annex.push(0x50);
    annex.extend_from_slice(blob);
    tx.input[0].witness.push(annex.as_slice());
}

/// Extract from annex if present (see [`attach_to_funding_witness`]).
pub fn extract_from_funding_witness(tx: &bitcoin::Transaction) -> Option<Vec<u8>> {
    let w = &tx.input.get(0)?.witness;
    if w.len() < 2 {
        return None;
    }
    let last = w.nth(w.len() - 1)?;
    if last.first() != Some(&0x50) {
        return None;
    }
    let blob = &last[1..];
    if blob.get(..4) == Some(MAGIC.as_slice()) {
        Some(blob.to_vec())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phase_a::flow::serialize_claim;
    use crate::ClaimMini;

    fn sample_claim_bytes() -> Vec<u8> {
        serialize_claim(&ClaimMini::make_valid(
            [1; 32],
            100,
            40,
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
        ))
    }

    #[test]
    fn roundtrip_direct() {
        let claim_bytes = sample_claim_bytes();
        let opening = AssertOpening::Direct(DirectSeedOpening::from_claim_bytes(0, &claim_bytes));
        let h = [0x11; 32];
        let w = AssertWitnessV1::new(claim_bytes, opening, h, None);
        let enc = w.encode();
        let dec = AssertWitnessV1::decode(&enc).unwrap();
        assert_eq!(dec.statement.h_l_invalid, h);
        assert!(matches!(dec.opening, AssertOpening::Direct(_)));
        dec.check_hashlock(&h).unwrap();
    }

    #[test]
    fn roundtrip_adaptor_with_bundle() {
        let claim_bytes = sample_claim_bytes();
        let (opening, _) = AdaptorOpening::create_ephemeral(0, &claim_bytes).unwrap();
        let bundle = ShareBundle::synthetic_from_adaptor_secret(&[9; 32]);
        let h = [0x22; 32];
        let w = AssertWitnessV1::new(
            claim_bytes,
            AssertOpening::Adaptor(opening),
            h,
            Some(bundle),
        );
        let dec = AssertWitnessV1::decode(&w.encode()).unwrap();
        assert!(dec.share_bundle.is_some());
        assert!(matches!(dec.opening, AssertOpening::Adaptor(_)));
    }

    #[test]
    fn tampered_claim_fails() {
        let claim_bytes = sample_claim_bytes();
        let opening = AssertOpening::Direct(DirectSeedOpening::from_claim_bytes(0, &claim_bytes));
        let mut w = AssertWitnessV1::new(claim_bytes, opening, [0; 32], None);
        w.claim_bytes[0] ^= 1;
        assert!(matches!(
            AssertWitnessV1::decode(&w.encode()),
            Err(WitnessError::ClaimHashMismatch)
        ));
    }

    #[cfg(feature = "gsv-vsss")]
    #[test]
    fn roundtrip_gsv_adaptor() {
        use ark_ff::UniformRand;
        use ark_secp256k1::Fr;
        use rand::thread_rng;
        let claim_bytes = sample_claim_bytes();
        let mut rng = thread_rng();
        let evaluator = Fr::rand(&mut rng);
        let garbler = Fr::rand(&mut rng);
        let opening =
            GsvAdaptorOpening::create(2, &claim_bytes, &evaluator, &garbler, &mut rng).unwrap();
        let w = AssertWitnessV1::new(
            claim_bytes,
            AssertOpening::GsvAdaptor(opening),
            [0x33; 32],
            None,
        );
        let dec = AssertWitnessV1::decode(&w.encode()).unwrap();
        match dec.opening {
            AssertOpening::GsvAdaptor(o) => assert_eq!(o.extract_fr().unwrap(), garbler),
            _ => panic!("expected GsvAdaptor"),
        }
    }

    #[test]
    fn ciphertext_hash_roundtrip_and_check() {
        let claim_bytes = sample_claim_bytes();
        let opening = AssertOpening::Direct(DirectSeedOpening::from_claim_bytes(0, &claim_bytes));
        let ct = [0xAB; 32];
        let w = AssertWitnessV1::new(claim_bytes, opening, [0; 32], None).with_ciphertext_hash(ct);
        let dec = AssertWitnessV1::decode(&w.encode()).unwrap();
        assert_eq!(dec.ciphertext_hash, Some(ct));
        dec.check_ciphertext_hash(&ct).unwrap();
        assert!(matches!(
            dec.check_ciphertext_hash(&[0; 32]),
            Err(WitnessError::CiphertextHashMismatch)
        ));
    }

    #[test]
    fn legacy_blob_without_ct_flag_decodes() {
        // Encode without trailing ct flag by truncating the final 0 byte.
        let claim_bytes = sample_claim_bytes();
        let opening = AssertOpening::Direct(DirectSeedOpening::from_claim_bytes(0, &claim_bytes));
        let mut enc = AssertWitnessV1::new(claim_bytes, opening, [0; 32], None).encode();
        assert_eq!(enc.pop(), Some(0)); // drop ct_flag=0
        let dec = AssertWitnessV1::decode(&enc).unwrap();
        assert!(dec.ciphertext_hash.is_none());
    }

    fn bare_tx() -> bitcoin::Transaction {
        use bitcoin::{absolute, transaction::Version, OutPoint, Sequence, TxIn, TxOut, Transaction};
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn op_return_roundtrip() {
        let claim_bytes = sample_claim_bytes();
        let opening = AssertOpening::Direct(DirectSeedOpening::from_claim_bytes(0, &claim_bytes));
        let blob = AssertWitnessV1::new(claim_bytes, opening, [0x33; 32], None).encode();
        let mut tx = bare_tx();
        attach_op_return_output(&mut tx, &blob).unwrap();
        assert_eq!(extract_from_op_return(&tx).unwrap(), blob);
    }

    #[test]
    fn op_return_multi_push_roundtrip() {
        // Force >520-byte payload so the carrier uses multiple script pushes.
        let mut blob = MAGIC.to_vec();
        blob.extend(std::iter::repeat(0xABu8).take(600));
        let mut tx = bare_tx();
        attach_op_return_output(&mut tx, &blob).unwrap();
        assert_eq!(extract_from_op_return(&tx).unwrap(), blob);
    }
}
