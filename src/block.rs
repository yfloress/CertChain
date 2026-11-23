use serde::{Deserialize, Serialize};

use crate::Result;
use crate::crypto::KeyPair;
use crate::transaction::Transaction;
use crate::types::{Digest, PublicKey, Signature};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockHeader {
    pub height: u64,
    pub prev_hash: Digest,
    pub merkle_root: Digest,
    pub num_tx: u64,
    pub timestamp: u64,
    pub validator: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub header: BlockHeader,
    pub signature: Signature,
    pub transactions: Vec<Transaction>,
}

impl BlockHeader {
    pub fn hash(&self) -> Digest {
        todo!()
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        todo!()
    }
}

impl Block {
    /// Builds and signs a block; rejects an empty transaction list.
    pub fn seal(
        key: &KeyPair,
        height: u64,
        prev_hash: Digest,
        timestamp: u64,
        transactions: Vec<Transaction>,
    ) -> Result<Self> {
        todo!()
    }

    pub fn compute_merkle_root(&self) -> Digest {
        todo!()
    }
}
