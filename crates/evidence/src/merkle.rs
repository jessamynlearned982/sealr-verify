//! RFC 6962-style Merkle tree over BLAKE3-256 (doc 03 §8, ADR-003).
//!
//! Leaf hash:  `H(0x00 || leaf_bytes)`
//! Node hash:  `H(0x01 || left || right)`
//! Tree shape: recursive split at the largest power of two strictly less than n.
//!
//! Leaves are the raw 32-byte record hashes (decoded from `record_hash` hex) for
//! checkpoint trees, and raw checkpoint/batch digests for anchoring trees.

use crate::error::{EvidenceError, Result};
use crate::hash::DIGEST_LEN;

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// A 32-byte digest.
pub type Digest = [u8; DIGEST_LEN];

/// Hash a leaf per RFC 6962 conventions.
pub fn leaf_hash(leaf_bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(leaf_bytes);
    *hasher.finalize().as_bytes()
}

/// Hash an interior node per RFC 6962 conventions.
pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Largest power of two strictly less than `n` (n >= 2).
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Compute the Merkle tree hash over `leaves` (already leaf-level input bytes,
/// NOT pre-hashed). Empty input hashes the empty string per RFC 6962.
pub fn merkle_root(leaves: &[impl AsRef<[u8]>]) -> Digest {
    match leaves.len() {
        0 => *blake3::hash(b"").as_bytes(),
        _ => subtree_root(leaves),
    }
}

fn subtree_root(leaves: &[impl AsRef<[u8]>]) -> Digest {
    match leaves.len() {
        1 => leaf_hash(leaves[0].as_ref()),
        n => {
            let k = split_point(n);
            let left = subtree_root(&leaves[..k]);
            let right = subtree_root(&leaves[k..]);
            node_hash(&left, &right)
        }
    }
}

/// One step of an audit path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStep {
    /// Sibling digest.
    pub sibling: Digest,
    /// True when the sibling is on the left (i.e. our running hash is the right child).
    pub sibling_on_left: bool,
}

/// Compute the inclusion proof (audit path) for `index` within `leaves`.
pub fn inclusion_proof(leaves: &[impl AsRef<[u8]>], index: usize) -> Result<Vec<ProofStep>> {
    if index >= leaves.len() {
        return Err(EvidenceError::MerkleProof(format!(
            "index {index} out of range for tree of {} leaves",
            leaves.len()
        )));
    }
    let mut proof = Vec::new();
    path(leaves, index, &mut proof);
    Ok(proof)
}

fn path(leaves: &[impl AsRef<[u8]>], index: usize, proof: &mut Vec<ProofStep>) {
    let n = leaves.len();
    if n == 1 {
        return;
    }
    let k = split_point(n);
    if index < k {
        path(&leaves[..k], index, proof);
        proof.push(ProofStep {
            sibling: subtree_root(&leaves[k..]),
            sibling_on_left: false,
        });
    } else {
        path(&leaves[k..], index - k, proof);
        proof.push(ProofStep {
            sibling: subtree_root(&leaves[..k]),
            sibling_on_left: true,
        });
    }
}

/// Verify an inclusion proof: does `leaf_bytes` at `index` in a tree of
/// `tree_size` leaves hash up to `root` via `proof`?
pub fn verify_inclusion(
    leaf_bytes: &[u8],
    index: usize,
    tree_size: usize,
    proof: &[ProofStep],
    root: &Digest,
) -> Result<()> {
    if index >= tree_size {
        return Err(EvidenceError::MerkleProof(format!(
            "index {index} out of range for tree_size {tree_size}"
        )));
    }
    let mut hash = leaf_hash(leaf_bytes);
    for step in proof {
        hash = if step.sibling_on_left {
            node_hash(&step.sibling, &hash)
        } else {
            node_hash(&hash, &step.sibling)
        };
    }
    if &hash == root {
        Ok(())
    } else {
        Err(EvidenceError::MerkleProof(
            "recomputed root does not match".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hex_encode;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let l = leaves(1);
        assert_eq!(merkle_root(&l), leaf_hash(b"leaf-0"));
    }

    #[test]
    fn known_two_leaf_shape() {
        let l = leaves(2);
        let expected = node_hash(&leaf_hash(b"leaf-0"), &leaf_hash(b"leaf-1"));
        assert_eq!(merkle_root(&l), expected);
    }

    #[test]
    fn inclusion_proofs_verify_for_all_sizes_and_indices() {
        for n in 1..=33usize {
            let l = leaves(n);
            let root = merkle_root(&l);
            for i in 0..n {
                let proof = inclusion_proof(&l, i).unwrap();
                verify_inclusion(&l[i], i, n, &proof, &root).unwrap_or_else(|e| {
                    panic!("proof failed for n={n} i={i}: {e}");
                });
            }
        }
    }

    #[test]
    fn tampered_leaf_fails_verification() {
        let l = leaves(7);
        let root = merkle_root(&l);
        let proof = inclusion_proof(&l, 3).unwrap();
        assert!(verify_inclusion(b"leaf-X", 3, 7, &proof, &root).is_err());
    }

    #[test]
    fn root_changes_with_any_leaf_change() {
        let l1 = leaves(8);
        let mut l2 = leaves(8);
        l2[5] = b"tampered".to_vec();
        assert_ne!(hex_encode(&merkle_root(&l1)), hex_encode(&merkle_root(&l2)));
    }
}
