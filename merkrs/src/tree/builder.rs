//! Bottom-up construction and structural validation of the flat tree array.

use super::index::{left_child, right_child};
use crate::bytes::Bytes32;
use crate::error::{Error, Result};
use crate::hashes::NodeHashFn;

/// Build a complete binary Merkle tree from leaves.
///
/// Returns a flat array where index 0 is the root.
/// Leaves occupy the rightmost positions `[tree_len - n .. tree_len)` in reverse order.
pub(crate) fn build(leaves: &[Bytes32], node_hash: NodeHashFn) -> Result<Vec<Bytes32>> {
    if leaves.is_empty() {
        return Err(Error::EmptyLeaves);
    }

    let n = leaves.len();
    let tree_len = 2 * n - 1;
    let mut tree = vec![[0u8; 32]; tree_len];

    let leaf_start = tree_len - n;
    let leaf_slots = tree.get_mut(leaf_start..).ok_or(Error::EmptyLeaves)?;
    for (slot, leaf) in leaf_slots.iter_mut().rev().zip(leaves) {
        *slot = *leaf;
    }

    for i in (0..leaf_start).rev() {
        let l = left_child(i);
        let r = right_child(i);
        let lh = tree.get(l).ok_or(Error::IndexOutOfBounds {
            index: l,
            len: tree_len,
        })?;
        let rh = tree.get(r).ok_or(Error::IndexOutOfBounds {
            index: r,
            len: tree_len,
        })?;
        let hash = node_hash(lh, rh);
        *tree.get_mut(i).ok_or(Error::IndexOutOfBounds {
            index: i,
            len: tree_len,
        })? = hash;
    }

    Ok(tree)
}

/// Verify that a tree's internal hashes are consistent with `node_hash`.
pub(crate) fn is_valid(tree: &[Bytes32], node_hash: NodeHashFn) -> bool {
    if tree.is_empty() {
        return false;
    }
    for i in 0..tree.len() {
        let l = left_child(i);
        let r = right_child(i);
        match (tree.get(l), tree.get(r)) {
            (Some(lv), Some(rv)) => {
                let Some(node) = tree.get(i) else {
                    return false;
                };
                if *node != node_hash(lv, rv) {
                    return false;
                }
            }
            (Some(_), None) => return false,
            _ => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
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
    fn build_and_validate() {
        let leaves = test_leaves(4);
        let tree = build(&leaves, standard_node_hash).unwrap();
        assert_eq!(tree.len(), 7);
        assert!(is_valid(&tree, standard_node_hash));
    }

    #[test]
    fn single_leaf() {
        let leaves = test_leaves(1);
        let tree = build(&leaves, standard_node_hash).unwrap();
        assert_eq!(tree.len(), 1);
        assert!(is_valid(&tree, standard_node_hash));
    }

    #[test]
    fn empty_leaves_rejected() {
        let result = build(&[], standard_node_hash);
        assert!(matches!(result, Err(Error::EmptyLeaves)));
    }

    #[test]
    fn invalid_trees() {
        assert!(!is_valid(&[], standard_node_hash));
        assert!(!is_valid(&[[0u8; 32]; 2], standard_node_hash));
        assert!(!is_valid(&[[0u8; 32]; 3], standard_node_hash));
    }

    #[test]
    fn power_of_two_and_non_power() {
        for count in [2, 3, 4, 5, 7, 8, 9, 15, 16] {
            let leaves = test_leaves(count);
            let tree = build(&leaves, standard_node_hash).unwrap();
            assert_eq!(tree.len(), 2 * count - 1);
            assert!(is_valid(&tree, standard_node_hash));
        }
    }
}
