//! JSON persistence. Writes go to a temporary file and are then renamed.

use std::path::{Path, PathBuf};

use crate::Result;
use crate::chain::Chain;
use crate::crypto::KeyPair;
use crate::transaction::Transaction;

pub struct Storage {
    dir: PathBuf,
}

impl Storage {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn chain_path(&self) -> PathBuf {
        self.dir.join("chain.json")
    }

    pub fn pending_path(&self) -> PathBuf {
        self.dir.join("pending.json")
    }

    /// Returns an unvalidated chain.
    pub fn load_chain(&self) -> Result<Chain> {
        todo!()
    }

    pub fn save_chain(&self, chain: &Chain) -> Result<()> {
        todo!()
    }

    pub fn load_pending(&self) -> Result<Vec<Transaction>> {
        todo!()
    }

    pub fn save_pending(&self, pending: &[Transaction]) -> Result<()> {
        todo!()
    }
}

pub fn load_key(path: &Path) -> Result<KeyPair> {
    todo!()
}

/// Uses mode 0600 on Unix and never overwrites an existing key.
pub fn save_key(path: &Path, key: &KeyPair) -> Result<()> {
    todo!()
}
