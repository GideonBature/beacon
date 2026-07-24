//! Off-chain garbled ciphertext store (Cube / BitVM3 cut-and-choose).
//!
//! Ciphertexts stay **off-chain**; Assert only needs the commitment
//! (`ciphertext_hash`) plus extractable opening / `H(L*)`. Layout matches
//! garbled-snark-verifier’s file format when the `gsv` feature is on:
//! concatenated 16-byte big-endian `S` labels in `gc_{instance_id}.bin`.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Wire / disk format version for [`CiphertextMeta`].
pub const META_FORMAT_V1: u8 = 1;

/// Hash algorithm id for Blake3 accumulating CT hash (GSV / Phase C+).
pub const HASH_ALG_BLAKE3_ACCUM: &str = "blake3-accum";
/// Hash algorithm id for SHA256 of the whole stream file (stand-in / tests).
pub const HASH_ALG_SHA256_FILE: &str = "sha256-file";

/// Metadata for one cut-and-choose instance’s garbled stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextMeta {
    pub format: u8,
    pub instance_id: u32,
    /// Commitment checked when loading the stream.
    #[serde(with = "hex32")]
    pub ciphertext_hash: [u8; 32],
    pub hash_alg: String,
    pub seed: u64,
    pub true_wire: u128,
    pub false_wire: u128,
    #[serde(with = "hex32")]
    pub l_invalid: [u8; 32],
    #[serde(with = "hex32")]
    pub l_valid: [u8; 32],
    /// Relative filename under the store root (e.g. `gc_0.bin`).
    pub stream_file: String,
    /// Optional Phase C+ eval sidecar (`gc_{id}.eval.bin`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar_file: Option<String>,
    /// SHA256 of the sidecar bytes (when present).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex32_opt")]
    pub sidecar_hash: Option<[u8; 32]>,
}

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Json(serde_json::Error),
    NotFound(u32),
    HashMismatch {
        instance_id: u32,
        expected: [u8; 32],
        got: [u8; 32],
    },
    BadMeta(&'static str),
    SidecarMissing(u32),
    SidecarHashMismatch {
        instance_id: u32,
        expected: [u8; 32],
        got: [u8; 32],
    },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ciphertext store io: {e}"),
            Self::Json(e) => write!(f, "ciphertext store json: {e}"),
            Self::NotFound(id) => write!(f, "ciphertext store: instance {id} not found"),
            Self::HashMismatch {
                instance_id,
                expected,
                got,
            } => write!(
                f,
                "ciphertext store: instance {instance_id} hash mismatch expected={} got={}",
                hex::encode(expected),
                hex::encode(got)
            ),
            Self::BadMeta(m) => write!(f, "ciphertext store: bad meta ({m})"),
            Self::SidecarMissing(id) => {
                write!(f, "ciphertext store: sidecar missing for instance {id}")
            }
            Self::SidecarHashMismatch {
                instance_id,
                expected,
                got,
            } => write!(
                f,
                "ciphertext store: instance {instance_id} sidecar hash mismatch expected={} got={}",
                hex::encode(expected),
                hex::encode(got)
            ),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Directory-backed store: `{root}/gc_{id}.bin` + `{root}/gc_{id}.meta.json`.
#[derive(Clone, Debug)]
pub struct CiphertextStore {
    root: PathBuf,
}

impl CiphertextStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn stream_path(&self, instance_id: u32) -> PathBuf {
        self.root.join(format!("gc_{instance_id}.bin"))
    }

    pub fn meta_path(&self, instance_id: u32) -> PathBuf {
        self.root.join(format!("gc_{instance_id}.meta.json"))
    }

    pub fn write_meta(&self, meta: &CiphertextMeta) -> Result<(), StoreError> {
        if meta.format != META_FORMAT_V1 {
            return Err(StoreError::BadMeta("unsupported format"));
        }
        let path = self.meta_path(meta.instance_id);
        let tmp = path.with_extension("meta.json.tmp");
        let json = serde_json::to_vec_pretty(meta)?;
        fs::write(&tmp, json)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn load_meta(&self, instance_id: u32) -> Result<CiphertextMeta, StoreError> {
        let path = self.meta_path(instance_id);
        if !path.exists() {
            return Err(StoreError::NotFound(instance_id));
        }
        let bytes = fs::read(&path)?;
        let meta: CiphertextMeta = serde_json::from_slice(&bytes)?;
        if meta.format != META_FORMAT_V1 {
            return Err(StoreError::BadMeta("unsupported format"));
        }
        if meta.instance_id != instance_id {
            return Err(StoreError::BadMeta("instance_id mismatch"));
        }
        Ok(meta)
    }

    /// Write raw stream bytes and a SHA256-file meta (stand-in / unit tests).
    pub fn persist_bytes_sha256(
        &self,
        instance_id: u32,
        stream: &[u8],
        seed: u64,
        true_wire: u128,
        false_wire: u128,
        l_invalid: [u8; 32],
        l_valid: [u8; 32],
    ) -> Result<CiphertextMeta, StoreError> {
        let stream_file = format!("gc_{instance_id}.bin");
        let path = self.root.join(&stream_file);
        let mut f = File::create(&path)?;
        f.write_all(stream)?;
        f.flush()?;
        let ciphertext_hash = sha256_file(&path)?;
        let meta = CiphertextMeta {
            format: META_FORMAT_V1,
            instance_id,
            ciphertext_hash,
            hash_alg: HASH_ALG_SHA256_FILE.into(),
            seed,
            true_wire,
            false_wire,
            l_invalid,
            l_valid,
            stream_file,
            sidecar_file: None,
            sidecar_hash: None,
        };
        self.write_meta(&meta)?;
        Ok(meta)
    }

    pub fn sidecar_path(&self, instance_id: u32) -> PathBuf {
        self.root.join(format!("gc_{instance_id}.eval.bin"))
    }

    /// Write raw sidecar bytes and return SHA256.
    pub fn write_sidecar_bytes(
        &self,
        instance_id: u32,
        bytes: &[u8],
    ) -> Result<([u8; 32], String), StoreError> {
        let sidecar_file = format!("gc_{instance_id}.eval.bin");
        let path = self.root.join(&sidecar_file);
        let tmp = path.with_extension("eval.bin.tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &path)?;
        Ok((sha256_bytes(bytes), sidecar_file))
    }

    /// Load sidecar bytes and verify against meta (when meta lists a sidecar).
    pub fn open_sidecar_verified(
        &self,
        meta: &CiphertextMeta,
    ) -> Result<Vec<u8>, StoreError> {
        let (file, expected) = match (&meta.sidecar_file, &meta.sidecar_hash) {
            (Some(f), Some(h)) => (f.clone(), *h),
            _ => return Err(StoreError::SidecarMissing(meta.instance_id)),
        };
        let path = self.root.join(file);
        if !path.exists() {
            return Err(StoreError::SidecarMissing(meta.instance_id));
        }
        let bytes = fs::read(&path)?;
        let got = sha256_bytes(&bytes);
        if got != expected {
            return Err(StoreError::SidecarHashMismatch {
                instance_id: meta.instance_id,
                expected,
                got,
            });
        }
        Ok(bytes)
    }

    /// Load meta and verify the stream file matches `ciphertext_hash`.
    pub fn open_verified(&self, instance_id: u32) -> Result<(CiphertextMeta, PathBuf), StoreError> {
        let meta = self.load_meta(instance_id)?;
        let path = self.root.join(&meta.stream_file);
        if !path.exists() {
            return Err(StoreError::NotFound(instance_id));
        }
        let got = match meta.hash_alg.as_str() {
            HASH_ALG_SHA256_FILE => sha256_file(&path)?,
            HASH_ALG_BLAKE3_ACCUM => {
                #[cfg(feature = "gsv")]
                {
                    blake3_accum_file(&path)?
                }
                #[cfg(not(feature = "gsv"))]
                {
                    return Err(StoreError::BadMeta(
                        "blake3-accum requires the gsv feature",
                    ));
                }
            }
            _ => return Err(StoreError::BadMeta("unknown hash_alg")),
        };
        if got != meta.ciphertext_hash {
            return Err(StoreError::HashMismatch {
                instance_id,
                expected: meta.ciphertext_hash,
                got,
            });
        }
        Ok((meta, path))
    }

    /// Convenience: verify only (drop path).
    pub fn verify(&self, instance_id: u32) -> Result<CiphertextMeta, StoreError> {
        Ok(self.open_verified(instance_id)?.0)
    }
}

fn sha256_file(path: &Path) -> Result<[u8; 32], StoreError> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

pub(crate) fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(feature = "gsv")]
fn blake3_accum_file(path: &Path) -> Result<[u8; 32], StoreError> {
    use garbled_snark_verifier::circuit::ciphertext_source::{CiphertextSource, FileSource};
    let mut src = FileSource::from_path(path)?;
    while src.recv().is_some() {}
    Ok(src.finalize())
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&bytes);
        Ok(a)
    }
}

mod hex32_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(h) => s.serialize_some(&hex::encode(h)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes"));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&bytes);
                Ok(Some(a))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persist_and_verify_sha256() {
        let dir = std::env::temp_dir().join(format!(
            "beacon-ct-store-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let store = CiphertextStore::open(&dir).unwrap();
        let meta = store
            .persist_bytes_sha256(
                7,
                b"fake-gc-bytes-for-stand-in",
                42,
                1,
                0,
                [0x11; 32],
                [0x22; 32],
            )
            .unwrap();
        assert_eq!(meta.instance_id, 7);
        assert_eq!(meta.hash_alg, HASH_ALG_SHA256_FILE);
        let loaded = store.verify(7).unwrap();
        assert_eq!(loaded, meta);

        // Tamper stream → hash mismatch.
        fs::write(store.stream_path(7), b"tampered").unwrap();
        match store.verify(7) {
            Err(StoreError::HashMismatch { .. }) => {}
            other => panic!("expected HashMismatch, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
