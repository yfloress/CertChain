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

fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut buf = [0u8; 65];
    buf[0] = NODE_PREFIX;
    buf[1..33].copy_from_slice(&left.0);
    buf[33..].copy_from_slice(&right.0);
    sha256(&buf)
}

/// Largest power of two strictly smaller than `n` (requires `n > 1`).
fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// `leaves` are leaf hashes; the last one is never duplicated.
pub fn root(leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 => sha256(&[]),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
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

    const LEAVES: [&str; 8] = [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ];

    const ROOTS: [&str; 8] = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    fn leaves(n: usize) -> Vec<Digest> {
        LEAVES[..n]
            .iter()
            .map(|h| leaf_hash(&hex::decode(h).unwrap()))
            .collect()
    }

    #[test]
    fn leaf_hash_uses_prefix() {
        assert_eq!(leaf_hash(b"abc"), sha256(b"\x00abc"));
        assert_ne!(leaf_hash(b"abc"), sha256(b"abc"));
    }

    #[test]
    fn empty_root() {
        assert_eq!(root(&[]), sha256(b""));
    }

    #[test]
    fn roots_match_rfc_vectors() {
        for n in 1..=8 {
            assert_eq!(root(&leaves(n)).to_string(), ROOTS[n - 1], "n = {n}");
        }
    }

    #[test]
    fn last_leaf_is_not_duplicated() {
        let three = leaves(3);
        let mut four = three.clone();
        four.push(three[2]);
        assert_ne!(root(&three), root(&four));
    }
}
