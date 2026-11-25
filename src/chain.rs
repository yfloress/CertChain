use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::block::Block;
use crate::crypto::{self, KeyPair};
use crate::encoding::{Encoder, TAG_GENESIS};
use crate::transaction::{Emission, Revocation, Transaction};
use crate::types::{Digest, PublicKey};
use crate::{Error, Result};

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
        let mut encoder = Encoder::new(TAG_GENESIS).u64(self.timestamp);
        for list in [&self.issuers, &self.validators] {
            let count = u32::try_from(list.len()).expect("more than u32::MAX authorities");
            encoder = encoder.u32(count);
            for authority in list {
                encoder = encoder
                    .bytes(authority.name.as_bytes())
                    .fixed(&authority.public_key.0);
            }
        }
        crypto::sha256(&encoder.finish())
    }

    fn is_issuer(&self, key: &PublicKey) -> bool {
        self.issuers.iter().any(|a| a.public_key == *key)
    }

    fn is_validator(&self, key: &PublicKey) -> bool {
        self.validators.iter().any(|a| a.public_key == *key)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleError {
    UnauthorizedIssuer,
    Duplicate,
    RevocationWithoutEmission,
    RevokerIsNotIssuer,
}

impl RuleError {
    fn at(self, tx_index: usize) -> BlockError {
        match self {
            Self::UnauthorizedIssuer => BlockError::UnauthorizedIssuer { tx_index },
            Self::Duplicate => BlockError::DuplicateTx { tx_index },
            Self::RevocationWithoutEmission => BlockError::RevocationWithoutEmission { tx_index },
            Self::RevokerIsNotIssuer => BlockError::RevokerIsNotIssuer { tx_index },
        }
    }
}

impl From<RuleError> for Error {
    fn from(error: RuleError) -> Self {
        match error {
            RuleError::UnauthorizedIssuer => Self::Unauthorized,
            RuleError::Duplicate => Self::Duplicate,
            RuleError::RevocationWithoutEmission => {
                Self::Invalid("revocation without emission".into())
            }
            RuleError::RevokerIsNotIssuer => {
                Self::Invalid("revoker is not the original issuer".into())
            }
        }
    }
}

/// Certificates seen so far, to check issuers, duplicates and revocations.
struct Ledger<'a> {
    genesis: &'a Genesis,
    emitted: HashMap<Digest, PublicKey>,
    revoked: HashSet<Digest>,
}

impl<'a> Ledger<'a> {
    fn new(genesis: &'a Genesis) -> Self {
        Self {
            genesis,
            emitted: HashMap::new(),
            revoked: HashSet::new(),
        }
    }

    /// Records `tx`, or leaves the ledger unchanged if it breaks a rule.
    fn apply(&mut self, tx: &Transaction) -> std::result::Result<(), RuleError> {
        match tx {
            Transaction::Emission(tx) => {
                if !self.genesis.is_issuer(&tx.issuer) {
                    return Err(RuleError::UnauthorizedIssuer);
                }
                if self.emitted.contains_key(&tx.cert_hash) {
                    return Err(RuleError::Duplicate);
                }
                self.emitted.insert(tx.cert_hash, tx.issuer);
            }
            Transaction::Revocation(tx) => {
                let issuer = self
                    .emitted
                    .get(&tx.cert_hash)
                    .ok_or(RuleError::RevocationWithoutEmission)?;
                if *issuer != tx.issuer {
                    return Err(RuleError::RevokerIsNotIssuer);
                }
                if !self.revoked.insert(tx.cert_hash) {
                    return Err(RuleError::Duplicate);
                }
            }
        }
        Ok(())
    }
}

/// Checks everything except the Merkle root and the transactions.
fn check_header(
    genesis: &Genesis,
    block: &Block,
    height: u64,
    prev_hash: &Digest,
    prev_timestamp: u64,
) -> Vec<BlockError> {
    let header = &block.header;
    let mut errors = Vec::new();
    if header.height != height {
        errors.push(BlockError::WrongHeight);
    }
    if header.prev_hash != *prev_hash {
        errors.push(BlockError::PrevHashMismatch);
    }
    if header.timestamp < prev_timestamp {
        errors.push(BlockError::InvalidTimestamp);
    }
    if block.transactions.is_empty() {
        errors.push(BlockError::EmptyBlock);
    }
    if header.num_tx != block.transactions.len() as u64 {
        errors.push(BlockError::TxCountMismatch);
    }
    if !genesis.is_validator(&header.validator) {
        errors.push(BlockError::UnauthorizedValidator);
    }
    if crypto::verify(&header.validator, &header.signing_bytes(), &block.signature).is_err() {
        errors.push(BlockError::InvalidBlockSignature);
    }
    errors
}

impl Chain {
    pub fn new(genesis: Genesis) -> Self {
        Self {
            genesis,
            blocks: Vec::new(),
        }
    }

    pub fn report(&self) -> ValidationReport {
        let mut ledger = Ledger::new(&self.genesis);
        let mut prev_hash = self.genesis.hash();
        let mut prev_timestamp = self.genesis.timestamp;
        let mut blocks = Vec::with_capacity(self.blocks.len());
        for (height, block) in (1..).zip(&self.blocks) {
            let mut errors = check_header(&self.genesis, block, height, &prev_hash, prev_timestamp);
            if block.compute_merkle_root() != block.header.merkle_root {
                errors.push(BlockError::MerkleRootMismatch);
            }
            for (tx_index, tx) in block.transactions.iter().enumerate() {
                if tx.verify_signature().is_err() {
                    errors.push(BlockError::InvalidTxSignature { tx_index });
                }
                if let Err(error) = ledger.apply(tx) {
                    errors.push(error.at(tx_index));
                }
            }
            blocks.push(BlockReport { height, errors });
            prev_hash = block.header.hash();
            prev_timestamp = block.header.timestamp;
        }
        ValidationReport { blocks }
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

    fn transactions(&self) -> impl Iterator<Item = (&Block, &Transaction)> {
        self.0
            .blocks
            .iter()
            .flat_map(|block| block.transactions.iter().map(move |tx| (block, tx)))
    }

    pub fn find_emission(&self, cert_hash: &Digest) -> Option<(&Block, &Emission)> {
        self.transactions().find_map(|(block, tx)| match tx {
            Transaction::Emission(tx) if tx.cert_hash == *cert_hash => Some((block, tx)),
            _ => None,
        })
    }

    pub fn find_revocation(&self, cert_hash: &Digest) -> Option<(&Block, &Revocation)> {
        self.transactions().find_map(|(block, tx)| match tx {
            Transaction::Revocation(tx) if tx.cert_hash == *cert_hash => Some((block, tx)),
            _ => None,
        })
    }

    /// Checks a new transaction against the chain and the pending ones.
    pub fn check_transaction(&self, pending: &[Transaction], tx: &Transaction) -> Result<()> {
        let mut ledger = Ledger::new(&self.0.genesis);
        for (_, known) in self.transactions() {
            ledger.apply(known)?;
        }
        for known in pending {
            ledger.apply(known)?;
        }
        ledger.apply(tx)?;
        tx.verify_signature()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;
    use crate::types::Signature;

    const ISSUER: PublicKey = PublicKey([1; 32]);
    const OTHER_ISSUER: PublicKey = PublicKey([2; 32]);
    const STRANGER: PublicKey = PublicKey([3; 32]);
    const CERT: Digest = Digest([9; 32]);

    fn authority(name: &str, public_key: PublicKey) -> Authority {
        Authority {
            name: name.into(),
            public_key,
        }
    }

    fn validator_key() -> KeyPair {
        KeyPair::from_secret_bytes(&[7; 32])
    }

    fn genesis() -> Genesis {
        Genesis {
            timestamp: 1000,
            issuers: vec![authority("A", ISSUER), authority("B", OTHER_ISSUER)],
            validators: vec![authority("V", validator_key().public_key())],
        }
    }

    fn emission(issuer: PublicKey, cert_hash: Digest) -> Transaction {
        Transaction::Emission(Emission {
            cert_hash,
            issuer,
            timestamp: 1000,
            signature: Signature([0; 64]),
        })
    }

    fn revocation(issuer: PublicKey, cert_hash: Digest) -> Transaction {
        Transaction::Revocation(Revocation {
            cert_hash,
            issuer,
            timestamp: 1000,
            reason: "error".into(),
            signature: Signature([0; 64]),
        })
    }

    fn header() -> BlockHeader {
        BlockHeader {
            height: 1,
            prev_hash: genesis().hash(),
            merkle_root: Digest([0; 32]),
            num_tx: 1,
            timestamp: 1000,
            validator: validator_key().public_key(),
        }
    }

    fn signed(key: &KeyPair, header: BlockHeader) -> Block {
        Block {
            signature: key.sign(&header.signing_bytes()),
            header,
            transactions: vec![emission(ISSUER, CERT)],
        }
    }

    fn header_errors(block: &Block) -> Vec<BlockError> {
        check_header(&genesis(), block, 1, &genesis().hash(), 1000)
    }

    // Skips validation: only for tests that need no Merkle root or signatures.
    fn unchecked(transactions: Vec<Transaction>) -> ValidatedChain {
        let mut block = signed(&validator_key(), header());
        block.transactions = transactions;
        ValidatedChain(Chain {
            genesis: genesis(),
            blocks: vec![block],
        })
    }

    // Expected value was computed outside this crate.
    #[test]
    fn genesis_hash_vector() {
        let genesis = Genesis {
            timestamp: 1000,
            issuers: vec![authority("U", PublicKey([0x11; 32]))],
            validators: vec![authority("V", PublicKey([0x22; 32]))],
        };
        assert_eq!(
            genesis.hash().to_string(),
            "ef2a4630a5dd8f662558bd83838c9d9b3af2863a018b8dfe77712bca53cec1a3"
        );
    }

    #[test]
    fn genesis_hash_separates_issuers_from_validators() {
        let mut moved = genesis();
        let authority = moved.issuers.pop().unwrap();
        moved.validators.insert(0, authority);
        assert_ne!(moved.hash(), genesis().hash());
    }

    #[test]
    fn empty_chain_is_valid() {
        assert!(Chain::new(genesis()).validate().is_ok());
    }

    #[test]
    fn accepts_good_header() {
        assert_eq!(header_errors(&signed(&validator_key(), header())), []);
    }

    #[test]
    fn rejects_resigned_bad_headers() {
        type Case = (fn(&mut BlockHeader), BlockError);
        let cases: [Case; 4] = [
            (|h| h.height = 2, BlockError::WrongHeight),
            (|h| h.prev_hash.0[0] ^= 1, BlockError::PrevHashMismatch),
            (|h| h.timestamp = 999, BlockError::InvalidTimestamp),
            (|h| h.num_tx = 2, BlockError::TxCountMismatch),
        ];
        for (edit, expected) in cases {
            let mut bad = header();
            edit(&mut bad);
            assert_eq!(header_errors(&signed(&validator_key(), bad)), [expected]);
        }
    }

    #[test]
    fn rejects_empty_block() {
        let mut bad = header();
        bad.num_tx = 0;
        let mut block = signed(&validator_key(), bad);
        block.transactions.clear();
        assert_eq!(header_errors(&block), [BlockError::EmptyBlock]);
    }

    #[test]
    fn rejects_edited_header() {
        let mut block = signed(&validator_key(), header());
        block.header.merkle_root.0[0] ^= 1;
        assert_eq!(header_errors(&block), [BlockError::InvalidBlockSignature]);
    }

    #[test]
    fn rejects_unauthorized_validator() {
        let intruder = KeyPair::from_secret_bytes(&[8; 32]);
        let mut bad = header();
        bad.validator = intruder.public_key();
        assert_eq!(
            header_errors(&signed(&intruder, bad)),
            [BlockError::UnauthorizedValidator]
        );
    }

    #[test]
    fn reports_several_errors() {
        let mut block = signed(&validator_key(), header());
        block.header.height = 5;
        assert_eq!(
            header_errors(&block),
            [BlockError::WrongHeight, BlockError::InvalidBlockSignature]
        );
    }

    #[test]
    fn ledger_accepts_emission_then_revocation() {
        let genesis = genesis();
        let mut ledger = Ledger::new(&genesis);
        assert_eq!(ledger.apply(&emission(ISSUER, CERT)), Ok(()));
        assert_eq!(ledger.apply(&revocation(ISSUER, CERT)), Ok(()));
    }

    #[test]
    fn ledger_rejects_unauthorized_issuer() {
        let genesis = genesis();
        let mut ledger = Ledger::new(&genesis);
        assert_eq!(
            ledger.apply(&emission(STRANGER, CERT)),
            Err(RuleError::UnauthorizedIssuer)
        );
        // A rejected emission must not block the real one.
        assert_eq!(ledger.apply(&emission(ISSUER, CERT)), Ok(()));
    }

    #[test]
    fn ledger_rejects_duplicates() {
        let genesis = genesis();
        let mut ledger = Ledger::new(&genesis);
        ledger.apply(&emission(ISSUER, CERT)).unwrap();
        assert_eq!(
            ledger.apply(&emission(OTHER_ISSUER, CERT)),
            Err(RuleError::Duplicate)
        );
        ledger.apply(&revocation(ISSUER, CERT)).unwrap();
        assert_eq!(
            ledger.apply(&revocation(ISSUER, CERT)),
            Err(RuleError::Duplicate)
        );
        assert_eq!(
            ledger.apply(&emission(ISSUER, CERT)),
            Err(RuleError::Duplicate)
        );
    }

    #[test]
    fn ledger_rejects_bad_revocations() {
        let genesis = genesis();
        let mut ledger = Ledger::new(&genesis);
        assert_eq!(
            ledger.apply(&revocation(ISSUER, CERT)),
            Err(RuleError::RevocationWithoutEmission)
        );
        ledger.apply(&emission(ISSUER, CERT)).unwrap();
        for key in [OTHER_ISSUER, STRANGER] {
            assert_eq!(
                ledger.apply(&revocation(key, CERT)),
                Err(RuleError::RevokerIsNotIssuer)
            );
        }
    }

    #[test]
    fn finds_transactions() {
        let chain = unchecked(vec![emission(ISSUER, CERT), revocation(ISSUER, CERT)]);
        let (block, tx) = chain.find_emission(&CERT).unwrap();
        assert_eq!((block.header.height, tx.issuer), (1, ISSUER));
        assert_eq!(chain.find_revocation(&CERT).unwrap().1.reason, "error");
        assert!(chain.find_emission(&Digest([8; 32])).is_none());
        assert!(chain.find_revocation(&Digest([8; 32])).is_none());
    }

    #[test]
    fn check_transaction_rejects_before_signature() {
        let chain = unchecked(vec![emission(ISSUER, CERT)]);
        let other = Digest([8; 32]);
        let pending = [emission(ISSUER, other)];
        let check = |tx| chain.check_transaction(&pending, &tx);
        assert!(matches!(
            check(emission(ISSUER, CERT)),
            Err(Error::Duplicate)
        ));
        assert!(matches!(
            check(emission(ISSUER, other)),
            Err(Error::Duplicate)
        ));
        assert!(matches!(
            check(emission(STRANGER, Digest([7; 32]))),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            check(revocation(OTHER_ISSUER, CERT)),
            Err(Error::Invalid(_))
        ));
    }
}
