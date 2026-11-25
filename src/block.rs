use serde::{Deserialize, Serialize};

use crate::Result;
use crate::crypto::{self, KeyPair};
use crate::encoding::{Encoder, TAG_BLOCK_HASH, TAG_BLOCK_SIGNATURE};
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
        crypto::sha256(&self.encode(TAG_BLOCK_HASH))
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        self.encode(TAG_BLOCK_SIGNATURE)
    }

    fn encode(&self, tag: &str) -> Vec<u8> {
        Encoder::new(tag)
            .u64(self.height)
            .fixed(&self.prev_hash.0)
            .fixed(&self.merkle_root.0)
            .u64(self.num_tx)
            .u64(self.timestamp)
            .fixed(&self.validator.0)
            .finish()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> BlockHeader {
        BlockHeader {
            height: 1,
            prev_hash: Digest([0x11; 32]),
            merkle_root: Digest([0x22; 32]),
            num_tx: 2,
            timestamp: 1000,
            validator: PublicKey([0x33; 32]),
        }
    }

    // Expected values were computed outside this crate.
    #[test]
    fn hash_vector() {
        assert_eq!(
            header().hash().to_string(),
            "a6ecb87440afaef915867ff913335327e978b1c45165fdbcb2ae2392d9b7857b"
        );
    }

    #[test]
    fn signing_bytes_vector() {
        let expected = concat!(
            "00000019",
            "43657274436861696e2f76312f4649524d415f424c4f515545",
            "0000000000000001",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "0000000000000002",
            "00000000000003e8",
            "3333333333333333333333333333333333333333333333333333333333333333",
        );
        assert_eq!(hex::encode(header().signing_bytes()), expected);
    }

    #[test]
    fn every_field_changes_the_hash() {
        let edits: [fn(&mut BlockHeader); 6] = [
            |h| h.height += 1,
            |h| h.prev_hash.0[0] ^= 1,
            |h| h.merkle_root.0[0] ^= 1,
            |h| h.num_tx += 1,
            |h| h.timestamp += 1,
            |h| h.validator.0[0] ^= 1,
        ];
        for edit in edits {
            let mut changed = header();
            edit(&mut changed);
            assert_ne!(changed.hash(), header().hash());
            assert_ne!(changed.signing_bytes(), header().signing_bytes());
        }
    }
}
