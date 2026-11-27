use serde::{Deserialize, Serialize};

use crate::Result;
use crate::crypto::{self, KeyPair};
use crate::encoding::{Encoder, TAG_EMISSION, TAG_REVOCATION, TAG_TRANSACTION};
use crate::types::{Digest, PublicKey, Signature};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Transaction {
    Emission(Emission),
    Revocation(Revocation),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Emission {
    pub cert_hash: Digest,
    pub issuer: PublicKey,
    pub timestamp: u64,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub cert_hash: Digest,
    pub issuer: PublicKey,
    pub timestamp: u64,
    pub reason: String,
    pub signature: Signature,
}

impl Transaction {
    pub fn emission(key: &KeyPair, cert_hash: Digest, timestamp: u64) -> Self {
        let mut tx = Self::Emission(Emission {
            cert_hash,
            issuer: key.public_key(),
            timestamp,
            signature: Signature([0; 64]),
        });
        tx.sign_with(key);
        tx
    }

    pub fn revocation(key: &KeyPair, cert_hash: Digest, timestamp: u64, reason: String) -> Self {
        let mut tx = Self::Revocation(Revocation {
            cert_hash,
            issuer: key.public_key(),
            timestamp,
            reason,
            signature: Signature([0; 64]),
        });
        tx.sign_with(key);
        tx
    }

    fn sign_with(&mut self, key: &KeyPair) {
        let signature = key.sign(&self.signing_bytes());
        match self {
            Self::Emission(tx) => tx.signature = signature,
            Self::Revocation(tx) => tx.signature = signature,
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Emission(tx) => tx.timestamp,
            Self::Revocation(tx) => tx.timestamp,
        }
    }

    pub fn signature(&self) -> &Signature {
        match self {
            Self::Emission(tx) => &tx.signature,
            Self::Revocation(tx) => &tx.signature,
        }
    }

    pub fn cert_hash(&self) -> &Digest {
        match self {
            Self::Emission(tx) => &tx.cert_hash,
            Self::Revocation(tx) => &tx.cert_hash,
        }
    }

    pub fn issuer(&self) -> &PublicKey {
        match self {
            Self::Emission(tx) => &tx.issuer,
            Self::Revocation(tx) => &tx.issuer,
        }
    }

    /// Bytes covered by the signature; the tag depends on the variant.
    pub fn signing_bytes(&self) -> Vec<u8> {
        match self {
            Self::Emission(tx) => Encoder::new(TAG_EMISSION)
                .fixed(&tx.cert_hash.0)
                .fixed(&tx.issuer.0)
                .u64(tx.timestamp)
                .finish(),
            Self::Revocation(tx) => Encoder::new(TAG_REVOCATION)
                .fixed(&tx.cert_hash.0)
                .fixed(&tx.issuer.0)
                .u64(tx.timestamp)
                .bytes(tx.reason.as_bytes())
                .finish(),
        }
    }

    /// Merkle leaf data: the full transaction, signature included.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let kind = match self {
            Self::Emission(_) => 0,
            Self::Revocation(_) => 1,
        };
        let mut encoder = Encoder::new(TAG_TRANSACTION)
            .u8(kind)
            .fixed(&self.cert_hash().0)
            .fixed(&self.issuer().0)
            .u64(self.timestamp());
        if let Self::Revocation(tx) = self {
            encoder = encoder.bytes(tx.reason.as_bytes());
        }
        encoder.fixed(&self.signature().0).finish()
    }

    /// Only checks the signature, not whether the issuer is authorized.
    pub fn verify_signature(&self) -> Result<()> {
        crypto::verify(self.issuer(), &self.signing_bytes(), self.signature())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_fields() {
        let tx = Transaction::Emission(Emission {
            cert_hash: Digest([1; 32]),
            issuer: PublicKey([2; 32]),
            timestamp: 3,
            signature: Signature([4; 64]),
        });
        let mut json = serde_json::to_value(&tx).unwrap();
        assert_eq!(
            serde_json::from_value::<Transaction>(json.clone()).unwrap(),
            tx
        );
        json["extra"] = true.into();
        assert!(serde_json::from_value::<Transaction>(json).is_err());
    }

    fn key() -> KeyPair {
        KeyPair::from_secret_bytes(&[5; 32])
    }

    #[test]
    fn signed_transactions_verify() {
        let key = key();
        assert!(
            Transaction::emission(&key, Digest([1; 32]), 10)
                .verify_signature()
                .is_ok()
        );
        assert!(
            Transaction::revocation(&key, Digest([1; 32]), 20, "error en notas".into())
                .verify_signature()
                .is_ok()
        );
    }

    #[test]
    fn signature_covers_every_field() {
        let key = key();
        let Transaction::Emission(emission) = Transaction::emission(&key, Digest([1; 32]), 10)
        else {
            unreachable!()
        };
        let mut tx = emission.clone();
        tx.timestamp = 11;
        assert!(Transaction::Emission(tx).verify_signature().is_err());
        let mut tx = emission.clone();
        tx.cert_hash = Digest([2; 32]);
        assert!(Transaction::Emission(tx).verify_signature().is_err());
        let mut tx = emission;
        tx.issuer = KeyPair::from_secret_bytes(&[6; 32]).public_key();
        assert!(Transaction::Emission(tx).verify_signature().is_err());

        let Transaction::Revocation(mut revocation) =
            Transaction::revocation(&key, Digest([1; 32]), 20, "error en notas".into())
        else {
            unreachable!()
        };
        revocation.reason = "otro motivo".into();
        assert!(
            Transaction::Revocation(revocation)
                .verify_signature()
                .is_err()
        );
    }

    /// Attack: copy an emission's signature into a revocation.
    #[test]
    fn emission_signature_is_not_a_revocation_signature() {
        let key = key();
        let emission = Transaction::emission(&key, Digest([1; 32]), 10);
        let forged = Transaction::Revocation(Revocation {
            cert_hash: Digest([1; 32]),
            issuer: key.public_key(),
            timestamp: 10,
            reason: String::new(),
            signature: *emission.signature(),
        });
        assert!(forged.verify_signature().is_err());
    }

    #[test]
    fn leaf_bytes_include_type_and_signature() {
        let key = key();
        let emission = Transaction::emission(&key, Digest([1; 32]), 10);
        let revocation = Transaction::revocation(&key, Digest([1; 32]), 10, String::new());
        assert_ne!(emission.canonical_bytes(), revocation.canonical_bytes());
        let bytes = emission.canonical_bytes();
        assert!(bytes.ends_with(&emission.signature().0));
    }
}
