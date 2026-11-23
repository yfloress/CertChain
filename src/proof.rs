use serde::{Deserialize, Serialize};

use crate::Result;
use crate::block::BlockHeader;
use crate::chain::ValidatedChain;
use crate::transaction::Transaction;
use crate::types::Digest;

/// Contents of `prueba.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProof {
    pub block_height: u64,
    pub leaf_index: u64,
    pub path: Vec<Digest>,
    pub transaction: Transaction,
}

impl InclusionProof {
    pub fn build(chain: &ValidatedChain, cert_hash: &Digest) -> Result<Self> {
        todo!()
    }

    /// Tree size and root come from a trusted header, never from the proof.
    pub fn verify(&self, header: &BlockHeader) -> bool {
        todo!()
    }
}
