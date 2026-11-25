//! JSON persistence. Writes go to a temporary file and are then renamed.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::chain::Chain;
use crate::crypto::KeyPair;
use crate::transaction::Transaction;
use crate::{Error, Result};

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
        Ok(serde_json::from_slice(&fs::read(self.chain_path())?)?)
    }

    pub fn save_chain(&self, chain: &Chain) -> Result<()> {
        self.write_json(&self.chain_path(), chain)
    }

    /// A missing file means there is nothing pending.
    pub fn load_pending(&self) -> Result<Vec<Transaction>> {
        match fs::read(self.pending_path()) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn save_pending(&self, pending: &[Transaction]) -> Result<()> {
        self.write_json(&self.pending_path(), pending)
    }

    fn write_json<T: Serialize + ?Sized>(&self, path: &Path, value: &T) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(value)?;
        bytes.push(b'\n');
        fs::create_dir_all(&self.dir)?;
        let temp = path.with_extension("json.tmp");
        let mut file = File::create(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
        Ok(())
    }
}

/// The file holds the secret key as hex.
pub fn load_key(path: &Path) -> Result<KeyPair> {
    let text = fs::read_to_string(path)?;
    let mut secret = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut secret).map_err(|_| Error::InvalidKey)?;
    Ok(KeyPair::from_secret_bytes(&secret))
}

/// Uses mode 0600 on Unix and never overwrites an existing key.
pub fn save_key(path: &Path, key: &KeyPair) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    writeln!(file, "{}", hex::encode(key.secret_bytes()))?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{Authority, Genesis};
    use crate::transaction::Emission;
    use crate::types::{Digest, PublicKey, Signature};
    use tempfile::TempDir;

    fn chain(timestamp: u64) -> Chain {
        let authority = Authority {
            name: "Universidad Ñ".into(),
            public_key: PublicKey([1; 32]),
        };
        Chain::new(Genesis {
            timestamp,
            issuers: vec![authority.clone()],
            validators: vec![authority],
        })
    }

    fn transaction() -> Transaction {
        Transaction::Emission(Emission {
            cert_hash: Digest([2; 32]),
            issuer: PublicKey([1; 32]),
            timestamp: 5,
            signature: Signature([3; 64]),
        })
    }

    fn storage(dir: &TempDir) -> Storage {
        Storage::new(dir.path().join("datos"))
    }

    fn key() -> KeyPair {
        KeyPair::from_secret_bytes(&[7; 32])
    }

    #[test]
    fn chain_round_trip_and_overwrite() {
        let dir = TempDir::new().unwrap();
        let storage = storage(&dir);
        for timestamp in [1, 2] {
            storage.save_chain(&chain(timestamp)).unwrap();
            assert_eq!(storage.load_chain().unwrap(), chain(timestamp));
        }
    }

    #[test]
    fn pending_round_trip_and_clear() {
        let dir = TempDir::new().unwrap();
        let storage = storage(&dir);
        storage.save_pending(&[transaction()]).unwrap();
        assert_eq!(storage.load_pending().unwrap(), [transaction()]);
        storage.save_pending(&[]).unwrap();
        assert_eq!(storage.load_pending().unwrap(), []);
    }

    #[test]
    fn missing_files() {
        let dir = TempDir::new().unwrap();
        let storage = storage(&dir);
        assert_eq!(storage.load_pending().unwrap(), []);
        assert!(matches!(storage.load_chain(), Err(Error::Io(_))));
    }

    #[test]
    fn rejects_corrupt_json() {
        let dir = TempDir::new().unwrap();
        let storage = storage(&dir);
        storage.save_chain(&chain(1)).unwrap();
        fs::write(storage.chain_path(), "{").unwrap();
        fs::write(storage.pending_path(), "{").unwrap();
        assert!(matches!(storage.load_chain(), Err(Error::Json(_))));
        assert!(matches!(storage.load_pending(), Err(Error::Json(_))));
    }

    #[test]
    fn leaves_no_temporary_files() {
        let dir = TempDir::new().unwrap();
        let storage = storage(&dir);
        storage.save_chain(&chain(1)).unwrap();
        storage.save_pending(&[transaction()]).unwrap();
        let mut names: Vec<_> = fs::read_dir(dir.path().join("datos"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["chain.json", "pending.json"]);
    }

    #[test]
    fn failed_write_keeps_previous_file() {
        let dir = TempDir::new().unwrap();
        let storage = storage(&dir);
        storage.save_chain(&chain(1)).unwrap();
        // A directory in place of the temporary file makes the write fail.
        fs::create_dir(storage.chain_path().with_extension("json.tmp")).unwrap();
        assert!(storage.save_chain(&chain(2)).is_err());
        assert_eq!(storage.load_chain().unwrap(), chain(1));
    }

    #[test]
    fn key_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("u.key");
        save_key(&path, &key()).unwrap();
        let loaded = load_key(&path).unwrap();
        assert_eq!(loaded.secret_bytes(), key().secret_bytes());
    }

    #[test]
    fn never_overwrites_a_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("u.key");
        save_key(&path, &key()).unwrap();
        let other = KeyPair::from_secret_bytes(&[8; 32]);
        assert!(matches!(save_key(&path, &other), Err(Error::Io(_))));
        let loaded = load_key(&path).unwrap();
        assert_eq!(loaded.secret_bytes(), key().secret_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn key_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("u.key");
        save_key(&path, &key()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn rejects_invalid_keys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("u.key");
        for text in [
            String::new(),
            "abcd".into(),
            "zz".repeat(32),
            "ab".repeat(33),
        ] {
            fs::write(&path, text).unwrap();
            assert!(matches!(load_key(&path), Err(Error::InvalidKey)));
        }
    }
}
