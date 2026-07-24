//! GSV-compatible Schnorr adaptor opening (extractable Fr share).
//!
//! Matches `garbled_snark_verifier::cut_and_choose::vsss::adaptor::AdaptorInfo`:
//! completing a BIP340 signature under the **evaluator** key reveals the
//! **garbler Fr share**. Distinct from Phase B [`super::AdaptorOpening`]
//! (independent `t` + `CubePhaseBLabels` hash).
//!
//! Assert witness opening tag: `3` (`OPENING_GSV_ADAPTOR`).

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_secp256k1::{Fq, Fr, Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Protocol version for GSV-compatible openings.
pub const VERSION_GSV_ADAPTOR: u8 = 3;

/// BIP340 signature bytes (`R.x || s`), same as GSV `SignatureBytes`.
pub type GsvSignatureBytes = [u8; 64];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GsvAdaptorError {
    BadPoint,
    BadSignature(&'static str),
    Serialize,
}

impl std::fmt::Display for GsvAdaptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPoint => write!(f, "gsv adaptor: bad secp256k1 point"),
            Self::BadSignature(m) => write!(f, "gsv adaptor: {m}"),
            Self::Serialize => write!(f, "gsv adaptor: serialize/deserialize failed"),
        }
    }
}

impl std::error::Error for GsvAdaptorError {}

/// Incomplete adaptor info (serializable stand-in for GSV `AdaptorInfo` fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GsvAdaptorInfoBytes {
    /// Compressed `garbler_commit = share·G` (33 bytes).
    #[serde(with = "hex33")]
    pub garbler_commit: [u8; 33],
    /// Compressed evaluator nonce commitment (33 bytes).
    #[serde(with = "hex33")]
    pub evaluator_nonce_commit: [u8; 33],
    /// Evaluator partial `s` (Fr, **big-endian**).
    #[serde(with = "hex32")]
    pub evaluator_s: [u8; 32],
}

/// Self-contained Assert opening that yields a GSV Fr share.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GsvAdaptorOpening {
    pub version: u8,
    pub instance_id: u32,
    /// Evaluator BIP340 x-only pubkey (challenge Pk).
    #[serde(with = "hex32")]
    pub evaluator_xonly: [u8; 32],
    /// Message covered by the BIP340 signature.
    #[serde(with = "hex32")]
    pub message_hash: [u8; 32],
    /// `SHA256(claim_bytes)` for statement binding.
    #[serde(with = "hex32")]
    pub public_inputs_hash: [u8; 32],
    pub info: GsvAdaptorInfoBytes,
    /// Completed BIP340 signature (`R.x || s`).
    #[serde(with = "hex64")]
    pub completed_sig: GsvSignatureBytes,
}

/// Local copy of GSV `AdaptorInfo` math (fields accessible for serde).
#[derive(Clone, Debug)]
struct LocalAdaptor {
    garbler_commit: Projective,
    evaluator_nonce_commit: Projective,
    evaluator_s: Fr,
}

impl LocalAdaptor {
    fn new<R: RngCore + ?Sized>(
        evaluator_secret: &Fr,
        garbler_commit: Projective,
        message_hash: &[u8],
        rng: &mut R,
    ) -> Self {
        let mut nonce = Fr::rand(rng);
        let nonce_commit = Projective::generator() * nonce;
        let eval_pub = (Projective::generator() * *evaluator_secret).into_affine();
        let eval_pub_x = fq_to_be32(&affine_x(&eval_pub));

        let mut public_sum = garbler_commit + nonce_commit;
        if is_odd(&affine_y(&public_sum.into_affine())) {
            public_sum = -public_sum;
            nonce = -nonce;
        }
        let public_sum_bytes = fq_to_be32(&affine_x(&public_sum.into_affine()));

        let tag_hash = Sha256::digest(b"BIP0340/challenge");
        let mut hasher = Sha256::new();
        hasher.update(tag_hash);
        hasher.update(tag_hash);
        hasher.update(public_sum_bytes);
        hasher.update(eval_pub_x);
        hasher.update(message_hash);
        let e = Fr::from_be_bytes_mod_order(hasher.finalize().as_slice());
        let s = nonce + e * *evaluator_secret;

        Self {
            evaluator_nonce_commit: nonce_commit,
            garbler_commit,
            evaluator_s: s,
        }
    }

    fn extract_secret(&self, garbler_sig: &[u8]) -> Result<Fr, GsvAdaptorError> {
        if garbler_sig.len() != 64 {
            return Err(GsvAdaptorError::BadSignature("invalid signature length"));
        }
        let commit_sum = self.evaluator_nonce_commit + self.garbler_commit;
        let aff = commit_sum.into_affine();
        let odd = is_odd(&affine_y(&aff));
        let expected = fq_to_be32(&affine_x(&aff));
        if garbler_sig[0..32] != expected {
            return Err(GsvAdaptorError::BadSignature("unexpected nonce value"));
        }
        let garbler_s = Fr::from_be_bytes_mod_order(&garbler_sig[32..]);
        let diff = garbler_s - self.evaluator_s;
        Ok(if odd { -diff } else { diff })
    }

    fn garbler_signature(&self, secret: &Fr) -> GsvSignatureBytes {
        let commit_sum = self.evaluator_nonce_commit + self.garbler_commit;
        let odd = is_odd(&affine_y(&commit_sum.into_affine()));
        let (r, s) = if odd {
            (-commit_sum, self.evaluator_s - *secret)
        } else {
            (commit_sum, self.evaluator_s + *secret)
        };
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&fq_to_be32(&affine_x(&r.into_affine())));
        out[32..].copy_from_slice(&fr_to_be32(&s));
        out
    }

    fn to_bytes(&self) -> Result<GsvAdaptorInfoBytes, GsvAdaptorError> {
        Ok(GsvAdaptorInfoBytes {
            garbler_commit: compress_point(&self.garbler_commit)?,
            evaluator_nonce_commit: compress_point(&self.evaluator_nonce_commit)?,
            evaluator_s: fr_to_be32(&self.evaluator_s),
        })
    }

    fn from_bytes(bytes: &GsvAdaptorInfoBytes) -> Result<Self, GsvAdaptorError> {
        Ok(Self {
            garbler_commit: decompress_point(&bytes.garbler_commit)?,
            evaluator_nonce_commit: decompress_point(&bytes.evaluator_nonce_commit)?,
            evaluator_s: Fr::from_be_bytes_mod_order(&bytes.evaluator_s),
        })
    }
}

impl GsvAdaptorOpening {
    /// Domain-separated message hash bound to the claim.
    pub fn claim_message_hash(public_inputs_hash: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"Beacon/GsvAdaptor/Assert/v1");
        hasher.update(public_inputs_hash);
        hasher.finalize().into()
    }

    /// Create incomplete adaptor + completed garbler signature for `garbler_fr`.
    pub fn create<R: RngCore + CryptoRng>(
        instance_id: u32,
        claim_bytes: &[u8],
        evaluator_secret: &Fr,
        garbler_fr: &Fr,
        rng: &mut R,
    ) -> Result<Self, GsvAdaptorError> {
        let public_inputs_hash = sha256(claim_bytes);
        let message_hash = Self::claim_message_hash(&public_inputs_hash);
        let evaluator_xonly = xonly_from_fr(evaluator_secret)?;
        let garbler_commit = Projective::generator() * *garbler_fr;
        let local = LocalAdaptor::new(evaluator_secret, garbler_commit, &message_hash, rng);
        let completed_sig = local.garbler_signature(garbler_fr);
        Ok(Self {
            version: VERSION_GSV_ADAPTOR,
            instance_id,
            evaluator_xonly,
            message_hash,
            public_inputs_hash,
            info: local.to_bytes()?,
            completed_sig,
        })
    }

    /// Create with a random garbler Fr share.
    pub fn create_ephemeral<R: RngCore + CryptoRng>(
        instance_id: u32,
        claim_bytes: &[u8],
        evaluator_secret: &Fr,
        rng: &mut R,
    ) -> Result<(Self, Fr), GsvAdaptorError> {
        let garbler_fr = Fr::rand(rng);
        let opening = Self::create(
            instance_id,
            claim_bytes,
            evaluator_secret,
            &garbler_fr,
            rng,
        )?;
        Ok((opening, garbler_fr))
    }

    /// Recover garbler Fr share (GSV `extract_secret` semantics).
    pub fn extract_fr(&self) -> Result<Fr, GsvAdaptorError> {
        LocalAdaptor::from_bytes(&self.info)?.extract_secret(&self.completed_sig)
    }

    /// Fr share as **big-endian** 32 bytes (GSV adaptor wire).
    pub fn extract_fr_be32(&self) -> Result<[u8; 32], GsvAdaptorError> {
        Ok(fr_to_be32(&self.extract_fr()?))
    }

    /// Fr share as **little-endian** 32 bytes (Beacon `ShareBundle` / lagrange).
    pub fn extract_fr_le32(&self) -> Result<[u8; 32], GsvAdaptorError> {
        Ok(fr_to_le32(&self.extract_fr()?))
    }

    /// Label material for Phase C seed (domain-separated Fr BE).
    pub fn derive_label_material(&self) -> Result<[u8; 32], GsvAdaptorError> {
        let fr_be = self.extract_fr_be32()?;
        let mut hasher = Sha256::new();
        hasher.update(b"Beacon/GsvAdaptor/LabelMaterial/v1");
        hasher.update(self.instance_id.to_le_bytes());
        hasher.update(fr_be);
        Ok(hasher.finalize().into())
    }

    /// Encode opening fields (after AssertWitness opening tag).
    pub fn encode_fields(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(self.version);
        out.extend_from_slice(&self.instance_id.to_le_bytes());
        out.extend_from_slice(&self.evaluator_xonly);
        out.extend_from_slice(&self.message_hash);
        out.extend_from_slice(&self.public_inputs_hash);
        out.extend_from_slice(&self.info.garbler_commit);
        out.extend_from_slice(&self.info.evaluator_nonce_commit);
        out.extend_from_slice(&self.info.evaluator_s);
        out.extend_from_slice(&self.completed_sig);
        out
    }

    /// Decode fields after the opening tag byte has been consumed.
    pub fn decode_fields(bytes: &[u8]) -> Result<Self, GsvAdaptorError> {
        let mut c = Cursor::new(bytes);
        let version = c.read_u8()?;
        if version != VERSION_GSV_ADAPTOR {
            return Err(GsvAdaptorError::BadSignature("bad gsv adaptor version"));
        }
        let instance_id = c.read_u32()?;
        let evaluator_xonly = c.read_array32()?;
        let message_hash = c.read_array32()?;
        let public_inputs_hash = c.read_array32()?;
        let garbler_commit = c.read_array33()?;
        let evaluator_nonce_commit = c.read_array33()?;
        let evaluator_s = c.read_array32()?;
        let completed_sig = c.read_array64()?;
        if !c.is_empty() {
            return Err(GsvAdaptorError::BadSignature("trailing bytes"));
        }
        Ok(Self {
            version,
            instance_id,
            evaluator_xonly,
            message_hash,
            public_inputs_hash,
            info: GsvAdaptorInfoBytes {
                garbler_commit,
                evaluator_nonce_commit,
                evaluator_s,
            },
            completed_sig,
        })
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn fr_to_be32(x: &Fr) -> [u8; 32] {
    x.into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("Fr encodes to 32 bytes")
}

fn fr_to_le32(x: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = x.into_bigint().to_bytes_le();
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

fn xonly_from_fr(sk: &Fr) -> Result<[u8; 32], GsvAdaptorError> {
    let aff = (Projective::generator() * *sk).into_affine();
    Ok(fq_to_be32(&affine_x(&aff)))
}

fn fq_to_be32(x: &Fq) -> [u8; 32] {
    x.into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("Fq encodes to 32 bytes")
}

fn affine_x(a: &ark_secp256k1::Affine) -> Fq {
    a.x().expect("finite point")
}

fn affine_y(a: &ark_secp256k1::Affine) -> Fq {
    a.y().expect("finite point")
}

fn is_odd(y: &Fq) -> bool {
    y.into_bigint().is_odd()
}

fn compress_point(p: &Projective) -> Result<[u8; 33], GsvAdaptorError> {
    let mut buf = Vec::with_capacity(33);
    p.serialize_compressed(&mut buf)
        .map_err(|_| GsvAdaptorError::Serialize)?;
    if buf.len() != 33 {
        return Err(GsvAdaptorError::Serialize);
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&buf);
    Ok(out)
}

fn decompress_point(bytes: &[u8; 33]) -> Result<Projective, GsvAdaptorError> {
    Projective::deserialize_compressed(&mut &bytes[..]).map_err(|_| GsvAdaptorError::BadPoint)
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
    fn read_exact(&mut self, n: usize) -> Result<&'a [u8], GsvAdaptorError> {
        if self.pos + n > self.buf.len() {
            return Err(GsvAdaptorError::BadSignature("truncated"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn read_u8(&mut self) -> Result<u8, GsvAdaptorError> {
        Ok(self.read_exact(1)?[0])
    }
    fn read_u32(&mut self) -> Result<u32, GsvAdaptorError> {
        let b = self.read_exact(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn read_array32(&mut self) -> Result<[u8; 32], GsvAdaptorError> {
        let b = self.read_exact(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }
    fn read_array33(&mut self) -> Result<[u8; 33], GsvAdaptorError> {
        let b = self.read_exact(33)?;
        let mut a = [0u8; 33];
        a.copy_from_slice(b);
        Ok(a)
    }
    fn read_array64(&mut self) -> Result<[u8; 64], GsvAdaptorError> {
        let b = self.read_exact(64)?;
        let mut a = [0u8; 64];
        a.copy_from_slice(b);
        Ok(a)
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
        b.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod hex33 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        let s = String::deserialize(d)?;
        let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
        b.try_into()
            .map_err(|_| serde::de::Error::custom("expected 33 bytes"))
    }
}

mod hex64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
        b.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use garbled_snark_verifier::cut_and_choose::vsss::AdaptorInfo;
    use rand::thread_rng;

    #[test]
    fn extract_recovers_garbler_fr() {
        let mut rng = thread_rng();
        let evaluator = Fr::rand(&mut rng);
        let garbler = Fr::rand(&mut rng);
        let opening =
            GsvAdaptorOpening::create(7, b"claim", &evaluator, &garbler, &mut rng).unwrap();
        assert_eq!(opening.extract_fr().unwrap(), garbler);
        let enc = opening.encode_fields();
        let dec = GsvAdaptorOpening::decode_fields(&enc).unwrap();
        assert_eq!(dec.extract_fr().unwrap(), garbler);
        assert_eq!(dec.instance_id, 7);
    }

    #[test]
    fn matches_upstream_gsv_semantics() {
        let mut rng = thread_rng();
        let evaluator = Fr::rand(&mut rng);
        let garbler = Fr::rand(&mut rng);
        let commit = Projective::generator() * garbler;
        let msg = Sha256::digest(b"interop").to_vec();

        let upstream = AdaptorInfo::new(&evaluator, commit, &msg, &mut rng);
        let sig = upstream.garbler_signature(&garbler);
        assert_eq!(upstream.extract_secret(&sig).unwrap(), garbler);

        let local = LocalAdaptor::new(&evaluator, commit, &msg, &mut rng);
        let local_sig = local.garbler_signature(&garbler);
        assert_eq!(local.extract_secret(&local_sig).unwrap(), garbler);
    }

    #[test]
    fn label_material_stable_and_distinct_from_raw_fr() {
        let mut rng = thread_rng();
        let evaluator = Fr::rand(&mut rng);
        let garbler = Fr::rand(&mut rng);
        let o = GsvAdaptorOpening::create(0, b"x", &evaluator, &garbler, &mut rng).unwrap();
        let m = o.derive_label_material().unwrap();
        assert_eq!(m, o.derive_label_material().unwrap());
        assert_ne!(m, o.extract_fr_be32().unwrap());
    }
}
