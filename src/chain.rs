use serde::{Deserialize, Serialize};

use crate::Result;
use crate::block::Block;
use crate::crypto::KeyPair;
use crate::transaction::{Emission, Revocation, Transaction};
use crate::types::{Digest, PublicKey};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub name: String,
    pub public_key: PublicKey,
}

/// Trust anchor. Block 1 uses `Genesis::hash` as its `prev_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub timestamp: u64,
    pub issuers: Vec<Authority>,
    pub validators: Vec<Authority>,
}

impl Genesis {
    pub fn hash(&self) -> Digest {
        todo!()
    }
}

/// Untrusted chain, as read from disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    pub genesis: Genesis,
    pub blocks: Vec<Block>,
}

/// A chain that passed full validation; `Chain::validate` is the only way in.
#[derive(Debug)]
pub struct ValidatedChain(Chain);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockError {
    WrongHeight,
    PrevHashMismatch,
    MerkleRootMismatch,
    TxCountMismatch,
    EmptyBlock,
    UnauthorizedValidator,
    InvalidBlockSignature,
    InvalidTimestamp,
    UnauthorizedIssuer { tx_index: usize },
    InvalidTxSignature { tx_index: usize },
    DuplicateTx { tx_index: usize },
    RevocationWithoutEmission { tx_index: usize },
    RevokerIsNotIssuer { tx_index: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockReport {
    pub height: u64,
    pub errors: Vec<BlockError>,
}

/// One entry per block, so every failure can be shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub blocks: Vec<BlockReport>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        self.blocks.iter().all(|block| block.errors.is_empty())
    }
}

impl Chain {
    pub fn new(genesis: Genesis) -> Self {
        Self {
            genesis,
            blocks: Vec::new(),
        }
    }

    pub fn report(&self) -> ValidationReport {
        todo!()
    }

    pub fn validate(self) -> std::result::Result<ValidatedChain, ValidationReport> {
        let report = self.report();
        if report.is_valid() {
            Ok(ValidatedChain(self))
        } else {
            Err(report)
        }
    }
}

impl ValidatedChain {
    pub fn as_chain(&self) -> &Chain {
        &self.0
    }

    pub fn find_emission(&self, cert_hash: &Digest) -> Option<(&Block, &Emission)> {
        todo!()
    }

    pub fn find_revocation(&self, cert_hash: &Digest) -> Option<(&Block, &Revocation)> {
        todo!()
    }

    /// Checks a new transaction against the chain and the pending ones.
    pub fn check_transaction(&self, pending: &[Transaction], tx: &Transaction) -> Result<()> {
        todo!()
    }

    pub fn seal_block(
        &mut self,
        key: &KeyPair,
        timestamp: u64,
        transactions: Vec<Transaction>,
    ) -> Result<()> {
        todo!()
    }
}
