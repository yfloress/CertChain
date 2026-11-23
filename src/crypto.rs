//! SHA-256 hashing and Ed25519 keys.

use ed25519_dalek::SigningKey;

use crate::Result;
use crate::types::{Digest, PublicKey, Signature};

pub struct KeyPair {
    signing: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self> {
        todo!()
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(bytes),
        }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        todo!()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        todo!()
    }
}

pub fn sha256(data: &[u8]) -> Digest {
    use sha2::{Digest as _, Sha256};
    Digest(Sha256::digest(data).into())
}

/// Must use `verify_strict`, which rejects weak keys.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_abc() {
        assert_eq!(
            sha256(b"abc").to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
