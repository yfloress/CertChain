//! SHA-256 hashing and Ed25519 keys.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::types::{Digest, PublicKey, Signature};
use crate::{Error, Result};

pub struct KeyPair {
    signing: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Self::from_secret_bytes(&bytes))
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
        PublicKey(self.signing.verifying_key().to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.signing.sign(message).to_bytes())
    }
}

pub fn sha256(data: &[u8]) -> Digest {
    use sha2::{Digest as _, Sha256};
    Digest(Sha256::digest(data).into())
}

/// Must use `verify_strict`, which rejects weak keys.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    let key = VerifyingKey::from_bytes(&public_key.0).map_err(|_| Error::InvalidKey)?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature.0);
    key.verify_strict(message, &signature)
        .map_err(|_| Error::InvalidSignature)
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

    #[test]
    fn signature_round_trip() {
        let key = KeyPair::generate().unwrap();
        let signature = key.sign(b"mensaje");
        assert!(verify(&key.public_key(), b"mensaje", &signature).is_ok());
        let restored = KeyPair::from_secret_bytes(&key.secret_bytes());
        assert_eq!(restored.public_key(), key.public_key());
    }

    #[test]
    fn fails_if_message_changes() {
        let key = KeyPair::generate().unwrap();
        let signature = key.sign(b"mensaje");
        assert!(verify(&key.public_key(), b"mensajE", &signature).is_err());
    }

    #[test]
    fn fails_if_key_changes() {
        let key = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let signature = key.sign(b"mensaje");
        assert!(verify(&other.public_key(), b"mensaje", &signature).is_err());
    }

    #[test]
    fn fails_if_signature_changes() {
        let key = KeyPair::generate().unwrap();
        let mut signature = key.sign(b"mensaje");
        signature.0[0] ^= 1;
        assert!(verify(&key.public_key(), b"mensaje", &signature).is_err());
    }

    #[test]
    fn rejects_weak_key() {
        // Identity point: a small-order key that verify_strict must reject.
        let mut weak = [0u8; 32];
        weak[0] = 1;
        let result = verify(&PublicKey(weak), b"mensaje", &Signature([0; 64]));
        assert!(result.is_err());
    }
}
