//! Merkle tree as in RFC 9162, section 2.1.

use crate::crypto::sha256;
use crate::types::Digest;

pub const LEAF_PREFIX: u8 = 0x00;
pub const NODE_PREFIX: u8 = 0x01;

pub fn leaf_hash(data: &[u8]) -> Digest {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(data);
    sha256(&buf)
}

/// `leaves` are leaf hashes; the last one is never duplicated.
pub fn root(leaves: &[Digest]) -> Digest {
    todo!()
}

/// Sibling path for `index`, or `None` if out of range.
pub fn inclusion_path(leaves: &[Digest], index: u64) -> Option<Vec<Digest>> {
    todo!()
}

pub fn verify_inclusion(
    leaf: &Digest,
    index: u64,
    tree_size: u64,
    path: &[Digest],
    root: &Digest,
) -> bool {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_hash_uses_prefix() {
        assert_eq!(leaf_hash(b"abc"), sha256(b"\x00abc"));
        assert_ne!(leaf_hash(b"abc"), sha256(b"abc"));
    }
}
