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
    let index = usize::try_from(index).ok()?;
    if index >= leaves.len() {
        return None;
    }
    let mut path = Vec::new();
    collect_path(leaves, index, &mut path);
    Some(path)
}

fn collect_path(leaves: &[Digest], index: usize, path: &mut Vec<Digest>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split_point(n);
    if index < k {
        collect_path(&leaves[..k], index, path);
        path.push(root(&leaves[k..]));
    } else {
        collect_path(&leaves[k..], index - k, path);
        path.push(root(&leaves[..k]));
    }
}

pub fn verify_inclusion(
    leaf: &Digest,
    index: u64,
    tree_size: u64,
    path: &[Digest],
    root: &Digest,
) -> bool {
    if index >= tree_size {
        return false;
    }
    let mut node = index;
    let mut last = tree_size - 1;
    let mut hash = *leaf;
    for p in path {
        if last == 0 {
            return false;
        }
        if node & 1 == 1 || node == last {
            hash = node_hash(p, &hash);
            while node & 1 == 0 && node != 0 {
                node >>= 1;
                last >>= 1;
            }
        } else {
            hash = node_hash(&hash, p);
        }
        node >>= 1;
        last >>= 1;
    }
    last == 0 && hash == *root
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

    #[test]
    fn path_out_of_range() {
        assert_eq!(inclusion_path(&leaves(3), 3), None);
        assert_eq!(inclusion_path(&[], 0), None);
    }

    #[test]
    fn proofs_verify_for_every_leaf() {
        for n in [1, 2, 3, 5, 8] {
            let tree = leaves(n);
            let r = root(&tree);
            for (i, leaf) in tree.iter().enumerate() {
                let i = i as u64;
                let path = inclusion_path(&tree, i).unwrap();
                assert!(
                    verify_inclusion(leaf, i, n as u64, &path, &r),
                    "n={n} i={i}"
                );
            }
        }
    }

    #[test]
    fn altered_path_fails() {
        let tree = leaves(5);
        let r = root(&tree);
        let mut path = inclusion_path(&tree, 2).unwrap();
        path[0].0[0] ^= 1;
        assert!(!verify_inclusion(&tree[2], 2, 5, &path, &r));
        path.pop();
        assert!(!verify_inclusion(&tree[2], 2, 5, &path, &r));
    }

    #[test]
    fn altered_index_fails() {
        let tree = leaves(5);
        let r = root(&tree);
        let path = inclusion_path(&tree, 2).unwrap();
        assert!(!verify_inclusion(&tree[2], 3, 5, &path, &r));
        assert!(!verify_inclusion(&tree[2], 5, 5, &path, &r));
    }

    #[test]
    fn altered_size_fails() {
        let tree = leaves(5);
        let r = root(&tree);
        let path = inclusion_path(&tree, 4).unwrap();
        assert!(!verify_inclusion(&tree[4], 4, 6, &path, &r));
        assert!(!verify_inclusion(&tree[4], 4, 8, &path, &r));
    }

    #[test]
    fn altered_leaf_or_root_fails() {
        let tree = leaves(8);
        let r = root(&tree);
        let path = inclusion_path(&tree, 6).unwrap();
        assert!(!verify_inclusion(&tree[5], 6, 8, &path, &r));
        assert!(!verify_inclusion(&tree[6], 6, 8, &path, &tree[0]));
    }
}
