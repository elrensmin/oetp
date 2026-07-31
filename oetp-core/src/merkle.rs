// builds a Merkle tree of all packet hashes, root gets anchored to blockchain

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

const LEAF_PREFIX: &[u8] = b"oetp-leaf";
const INTERNAL_PREFIX: &[u8] = b"oetp-internal";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    levels: Vec<Vec<[u8; 32]>>,
    root: [u8; 32],
}

fn hash_leaf(data: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(LEAF_PREFIX);
    hasher.update(data);
    hasher.finalize().into()
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(INTERNAL_PREFIX);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub leaf: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

impl MerkleProof {
    pub fn verify(&self) -> bool {
        let mut current = hash_leaf(&self.leaf);
        let mut index = self.leaf_index;
        for sibling in &self.siblings {
            if index.is_multiple_of(2) {
                current = hash_pair(&current, sibling);
            } else {
                current = hash_pair(sibling, &current);
            }
            index /= 2
        }
        current == self.root
    }
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Result<Self> {
        if leaves.is_empty() {
            return Err(Error::InvalidInput(
                "Merkle tree needs at least one leaf".into(),
            ));
        }
        if leaves.len() > 1 << 20 {
            return Err(Error::InvalidInput(
                "too many leaves for Merkle tree".into(),
            ));
        }

        // Pre-hash leaves with domain separation
        let hashed_leaves: Vec<[u8; 32]> = leaves.iter().map(hash_leaf).collect();

        let mut levels = Vec::new();
        let mut current = hashed_leaves.clone();

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            for chunk in current.chunks(2) {
                if chunk.len() == 2 {
                    next.push(hash_pair(&chunk[0], &chunk[1]));
                } else {
                    // Odd node at end of level: carry up as-is (already domain-separated)
                    next.push(chunk[0]);
                }
            }
            levels.push(current);
            current = next;
        }

        let root = current[0];
        levels.push(vec![root]);

        Ok(Self {
            leaves,
            levels,
            root,
        })
    }

    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    pub fn prove(&self, leaf_index: usize) -> Result<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return Err(Error::InvalidInput("leaf index out of bounds".into()));
        }

        let mut siblings = Vec::new();
        let mut index = leaf_index;

        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_index = if index.is_multiple_of(2) { index + 1 } else { index - 1 };
            if sibling_index < level.len() {
                siblings.push(level[sibling_index]);
            }
            index /= 2;
        }

        Ok(MerkleProof {
            leaf_index: leaf_index as u64,
            leaf: self.leaves[leaf_index],
            siblings,
            root: self.root,
        })
    }

    pub fn verify_proof(proof: &MerkleProof) -> bool {
        proof.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(data: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = data;
        h
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let tree = MerkleTree::new(vec![leaf(1)]).unwrap();
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.root(), &hash_leaf(&leaf(1)));
    }

    #[test]
    fn test_merkle_tree_two_leaves() {
        let tree = MerkleTree::new(vec![leaf(1), leaf(2)]).unwrap();
        let expected = hash_pair(&hash_leaf(&leaf(1)), &hash_leaf(&leaf(2)));
        assert_eq!(tree.root(), &expected);
    }

    #[test]
    fn test_merkle_tree_four_leaves() {
        let leaves = vec![leaf(1), leaf(2), leaf(3), leaf(4)];
        let tree = MerkleTree::new(leaves).unwrap();
        let a = hash_pair(&hash_leaf(&leaf(1)), &hash_leaf(&leaf(2)));
        let b = hash_pair(&hash_leaf(&leaf(3)), &hash_leaf(&leaf(4)));
        let expected = hash_pair(&a, &b);
        assert_eq!(tree.root(), &expected);
    }

    #[test]
    fn test_merkle_tree_odd_leaves() {
        let leaves = vec![leaf(1), leaf(2), leaf(3)];
        let tree = MerkleTree::new(leaves).unwrap();
        let a = hash_pair(&hash_leaf(&leaf(1)), &hash_leaf(&leaf(2)));
        let expected = hash_pair(&a, &hash_leaf(&leaf(3)));
        assert_eq!(tree.root(), &expected);
    }

    #[test]
    fn test_merkle_tree_empty() {
        let err = MerkleTree::new(vec![]).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn test_merkle_proof_verify() {
        let leaves = vec![leaf(1), leaf(2), leaf(3), leaf(4)];
        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.prove(0).unwrap();
        assert!(proof.verify());
    }

    #[test]
    fn test_merkle_proof_verify_last_leaf() {
        let leaves = vec![leaf(1), leaf(2), leaf(3), leaf(4)];
        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.prove(3).unwrap();
        assert!(proof.verify());
    }

    #[test]
    fn test_merkle_proof_verify_odd_count() {
        let leaves = vec![leaf(1), leaf(2), leaf(3)];
        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.prove(1).unwrap();
        assert!(proof.verify());
    }

    #[test]
    fn test_merkle_proof_tampered_leaf_fails() {
        let leaves = vec![leaf(1), leaf(2), leaf(3), leaf(4)];
        let tree = MerkleTree::new(leaves).unwrap();
        let mut proof = tree.prove(0).unwrap();
        proof.leaf = leaf(99);
        assert!(!proof.verify());
    }

    #[test]
    fn test_merkle_proof_tampered_sibling_fails() {
        let leaves = vec![leaf(1), leaf(2), leaf(3), leaf(4)];
        let tree = MerkleTree::new(leaves).unwrap();
        let mut proof = tree.prove(0).unwrap();
        proof.siblings[0] = leaf(99);
        assert!(!proof.verify());
    }

    #[test]
    fn test_merkle_proof_out_of_bounds() {
        let tree = MerkleTree::new(vec![leaf(1)]).unwrap();
        let err = tree.prove(5).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn test_merkle_proof_different_trees_different_roots() {
        let t1 = MerkleTree::new(vec![leaf(1), leaf(2)]).unwrap();
        let t2 = MerkleTree::new(vec![leaf(1), leaf(3)]).unwrap();
        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn test_merkle_proof_verify_static() {
        let leaves = vec![leaf(1), leaf(2), leaf(3), leaf(4)];
        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.prove(2).unwrap();
        assert!(MerkleTree::verify_proof(&proof));
    }

    #[test]
    fn test_merkle_proof_second_preimage_resistance() {
        // A leaf hash should not equal an internal node hash
        let leaf_val = leaf(1);
        let leaf_hash = hash_leaf(&leaf_val);
        let internal_hash = hash_pair(&leaf_val, &leaf_val);
        assert_ne!(leaf_hash, internal_hash);
    }
}
