use serde::{Deserialize, Serialize};

use crate::Result;
use crate::crypto::KeyPair;
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
        todo!()
    }

    pub fn revocation(key: &KeyPair, cert_hash: Digest, timestamp: u64, reason: String) -> Self {
        todo!()
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
        todo!()
    }

    /// Merkle leaf data: the full transaction, signature included.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        todo!()
    }

    /// Only checks the signature, not whether the issuer is authorized.
    pub fn verify_signature(&self) -> Result<()> {
        todo!()
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
}
