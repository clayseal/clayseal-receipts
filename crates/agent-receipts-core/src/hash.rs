use sha2::{Digest, Sha256};

/// 32-byte SHA-256 digest (hex-serialized in JSON).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

pub fn hash_bytes(data: &[u8]) -> Hash32 {
    let digest = Sha256::digest(data);
    Hash32(digest.into())
}

pub fn hash_json<T: serde::Serialize>(value: &T) -> Result<Hash32, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hash_bytes(&bytes))
}
