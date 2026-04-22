//! Single-leaf Merkle proof generation and verification.

use super::index::{check_leaf, parent, sibling};
use crate::bytes::Bytes32;
use crate::error::{Error, Result};
use crate::hashes::NodeHashFn;

/// Generate a sibling-path proof for the leaf at `index`.
pub(crate) fn proof(tree: &[Bytes32], index: usize) -> Result<Vec<Bytes32>> {
    check_leaf(tree.len(), index)?;
    let mut path = Vec::new();
    let mut idx = index;
    while idx > 0 {
        let sib = sibling(idx)?;
        path.push(*tree.get(sib).ok_or(Error::IndexOutOfBounds {
            index: sib,
            len: tree.len(),
        })?);
        idx = parent(idx)?;
    }
    Ok(path)
}

/// Recompute the root from a leaf and its sibling-path proof.
pub(crate) fn process_proof(leaf: &Bytes32, proof: &[Bytes32], node_hash: NodeHashFn) -> Bytes32 {
    let mut current = *leaf;
    for sib in proof {
        current = node_hash(&current, sib);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::super::builder::build;
    use super::*;
    use crate::hashes::{keccak256, standard_node_hash};

    fn test_leaves(count: usize) -> Vec<Bytes32> {
        (0..count)
            .map(|i| {
                #[expect(clippy::cast_possible_truncation, reason = "test helper, i < 256")]
                let b = i as u8;
                keccak256(&[b])
            })
            .collect()
    }

    #[test]
    fn proof_roundtrip() {
        let leaves = test_leaves(8);
        let tree = build(&leaves, standard_node_hash).unwrap();
        let first_leaf = tree.len() - leaves.len();
        for i in first_leaf..tree.len() {
            let p = proof(&tree, i).unwrap();
            let root = process_proof(tree.get(i).unwrap(), &p, standard_node_hash);
            assert_eq!(root, *tree.first().unwrap(), "proof failed for index {i}");
        }
    }

    #[test]
    fn proof_for_internal_node_rejected() {
        let leaves = vec![[0u8; 32]; 2];
        let tree = build(&leaves, standard_node_hash).unwrap();
        assert!(matches!(proof(&tree, 0), Err(Error::NotALeaf(0))));
    }
}
