use std::collections::VecDeque;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::bytes::{Bytes32, bytes_to_hex, hex_to_bytes};
use crate::error::{Error, Result};
use crate::hashes::NodeHashFn;

#[inline]
const fn left_child(i: usize) -> usize {
    2 * i + 1
}

#[inline]
const fn right_child(i: usize) -> usize {
    2 * i + 2
}

#[inline]
const fn parent(i: usize) -> Result<usize> {
    if i == 0 {
        Err(Error::RootHasNoParent)
    } else {
        Ok((i - 1) / 2)
    }
}

#[inline]
const fn sibling(i: usize) -> Result<usize> {
    if i == 0 {
        Err(Error::RootHasNoSibling)
    } else if i % 2 == 1 {
        Ok(i + 1)
    } else {
        Ok(i - 1)
    }
}

#[inline]
const fn is_internal(tree_len: usize, i: usize) -> bool {
    left_child(i) < tree_len
}

#[inline]
const fn is_leaf(tree_len: usize, i: usize) -> bool {
    i < tree_len && !is_internal(tree_len, i)
}

fn check_leaf(tree_len: usize, i: usize) -> Result<()> {
    if is_leaf(tree_len, i) {
        Ok(())
    } else {
        Err(Error::NotALeaf(i))
    }
}

/// Build a complete binary Merkle tree from leaves.
///
/// Returns a flat array where index 0 is the root.
/// Leaves occupy the rightmost positions `[tree_len - n .. tree_len)`.
pub(crate) fn build(leaves: &[Bytes32], node_hash: NodeHashFn) -> Result<Vec<Bytes32>> {
    if leaves.is_empty() {
        return Err(Error::EmptyLeaves);
    }
    let n = leaves.len();
    let tree_len = 2 * n - 1;
    let mut tree = vec![[0u8; 32]; tree_len];

    for (i, leaf) in leaves.iter().enumerate() {
        tree[tree_len - 1 - i] = *leaf;
    }

    for i in (0..tree_len - n).rev() {
        tree[i] = node_hash(&tree[left_child(i)], &tree[right_child(i)]);
    }

    Ok(tree)
}

/// Generate a single-leaf Merkle proof (list of sibling hashes from leaf to root).
pub(crate) fn proof(tree: &[Bytes32], index: usize) -> Result<Vec<Bytes32>> {
    check_leaf(tree.len(), index)?;
    let mut result = Vec::new();
    let mut idx = index;
    while idx > 0 {
        result.push(tree[sibling(idx)?]);
        idx = parent(idx)?;
    }
    Ok(result)
}

/// Recompute the root from a leaf and its proof.
pub(crate) fn process_proof(
    leaf: &Bytes32,
    proof: &[Bytes32],
    node_hash: NodeHashFn,
) -> Bytes32 {
    let mut current = *leaf;
    for sib in proof {
        current = node_hash(&current, sib);
    }
    current
}

/// Verify that a Merkle tree's internal hashes are consistent.
pub(crate) fn is_valid(tree: &[Bytes32], node_hash: NodeHashFn) -> bool {
    if tree.is_empty() {
        return false;
    }
    for i in 0..tree.len() {
        let l = left_child(i);
        let r = right_child(i);
        if r < tree.len() {
            if tree[i] != node_hash(&tree[l], &tree[r]) {
                return false;
            }
        } else if l < tree.len() {
            // Unbalanced internal node with only a left child — invalid shape.
            return false;
        }
    }
    true
}

/// A multi-proof for proving multiple leaves at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiProof {
    /// Leaf hashes in tree order.
    pub leaves: Vec<Bytes32>,
    /// Auxiliary proof hashes.
    pub proof: Vec<Bytes32>,
    /// Flags: `true` = take next value from the leaf/result stack,
    /// `false` = take next value from proof.
    pub proof_flags: Vec<bool>,
}

/// Generate a multi-proof for the given leaf indices.
pub(crate) fn multi_proof(tree: &[Bytes32], indices: &[usize]) -> Result<MultiProof> {
    for &i in indices {
        check_leaf(tree.len(), i)?;
    }

    let mut sorted: Vec<usize> = indices.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));

    for w in sorted.windows(2) {
        if w[0] == w[1] {
            return Err(Error::DuplicateIndex(w[0]));
        }
    }

    let mut queue: VecDeque<usize> = sorted.iter().copied().collect();
    let mut proof_nodes = Vec::new();
    let mut flags = Vec::new();

    while let Some(j) = queue.pop_front() {
        if j == 0 {
            break;
        }
        let s = sibling(j)?;
        let p = parent(j)?;

        if queue.front() == Some(&s) {
            flags.push(true);
            queue.pop_front();
        } else {
            flags.push(false);
            proof_nodes.push(tree[s]);
        }
        queue.push_back(p);
    }

    if indices.is_empty() {
        proof_nodes.push(tree[0]);
    }

    let leaves: Vec<Bytes32> = sorted.iter().map(|&i| tree[i]).collect();

    Ok(MultiProof {
        leaves,
        proof: proof_nodes,
        proof_flags: flags,
    })
}

/// Recompute the root from a multi-proof.
pub(crate) fn process_multi_proof(mp: &MultiProof, node_hash: NodeHashFn) -> Result<Bytes32> {
    let proof_needed = mp.proof_flags.iter().filter(|&&f| !f).count();
    if mp.proof.len() < proof_needed {
        return Err(Error::InvalidMultiproof {
            expected: proof_needed,
            got: mp.proof.len(),
        });
    }
    if mp.leaves.len() + mp.proof.len() != mp.proof_flags.len() + 1 {
        return Err(Error::IncompatibleMultiproof {
            leaves: mp.leaves.len(),
            proof: mp.proof.len(),
            flags: mp.proof_flags.len(),
        });
    }

    let mut stack: VecDeque<Bytes32> = mp.leaves.iter().copied().collect();
    let mut proof_iter = mp.proof.iter();

    for &flag in &mp.proof_flags {
        let a = stack
            .pop_front()
            .ok_or(Error::MultiproofUnderflow("stack empty for first operand"))?;
        let b = if flag {
            stack
                .pop_front()
                .ok_or(Error::MultiproofUnderflow("stack empty for second operand"))?
        } else {
            *proof_iter
                .next()
                .ok_or(Error::MultiproofUnderflow("proof exhausted"))?
        };
        stack.push_back(node_hash(&a, &b));
    }

    let remaining: usize = stack.len() + proof_iter.count();
    if remaining != 1 {
        return Err(Error::MultiproofUnderflow(
            "stack + proof should have exactly one element",
        ));
    }

    Ok(stack.pop_front().unwrap_or_else(|| {
        // proof_iter had the last element — but we already consumed the iterator.
        // This branch is unreachable because remaining == 1 and stack is empty
        // would mean proof_iter.count() == 1, but we already called .count() above.
        // Safety: we handle this via the error above.
        [0u8; 32]
    }))
}

/// Render a tree as an indented string for debugging.
pub(crate) fn render(tree: &[Bytes32]) -> Result<String> {
    if tree.is_empty() {
        return Err(Error::EmptyLeaves);
    }

    let mut output = String::new();
    let mut stack: Vec<(usize, Vec<bool>)> = vec![(0, vec![])];

    while let Some((i, path)) = stack.pop() {
        for &is_continuation in path.iter().take(path.len().saturating_sub(1)) {
            output.push_str(if is_continuation { "│  " } else { "   " });
        }
        if let Some(&is_left) = path.last() {
            output.push_str(if is_left { "├─ " } else { "└─ " });
        }

        use fmt::Write;
        let _ = writeln!(output, "{i}) {}", bytes_to_hex(&tree[i]));

        let r = right_child(i);
        if r < tree.len() {
            let mut right_path = path.clone();
            right_path.push(false);
            stack.push((r, right_path));

            let mut left_path = path;
            left_path.push(true);
            stack.push((left_child(i), left_path));
        }
    }

    // Remove trailing newline
    if output.ends_with('\n') {
        output.pop();
    }

    Ok(output)
}

/// Serde-compatible multi-proof for JSON serialization (hex strings, camelCase).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiProofJson {
    /// Leaf hashes as hex strings.
    pub leaves: Vec<String>,
    /// Auxiliary proof hashes as hex strings.
    pub proof: Vec<String>,
    /// Flags indicating whether to consume from the stack or from the proof.
    pub proof_flags: Vec<bool>,
}

impl TryFrom<MultiProofJson> for MultiProof {
    type Error = Error;

    fn try_from(json: MultiProofJson) -> Result<Self> {
        let leaves = json
            .leaves
            .iter()
            .map(|s| hex_to_bytes(s))
            .collect::<Result<Vec<_>>>()?;
        let proof = json
            .proof
            .iter()
            .map(|s| hex_to_bytes(s))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            leaves,
            proof,
            proof_flags: json.proof_flags,
        })
    }
}

impl From<&MultiProof> for MultiProofJson {
    fn from(mp: &MultiProof) -> Self {
        Self {
            leaves: mp.leaves.iter().map(bytes_to_hex).collect(),
            proof: mp.proof.iter().map(bytes_to_hex).collect(),
            proof_flags: mp.proof_flags.clone(),
        }
    }
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
    fn proof_roundtrip() {
        let leaves = test_leaves(8);
        let tree = build(&leaves, standard_node_hash).unwrap();
        let first_leaf = tree.len() - leaves.len();
        for i in first_leaf..tree.len() {
            let p = proof(&tree, i).unwrap();
            let root = process_proof(&tree[i], &p, standard_node_hash);
            assert_eq!(root, tree[0], "proof failed for index {i}");
        }
    }

    #[test]
    fn multi_proof_roundtrip() {
        let leaves = test_leaves(4);
        let tree = build(&leaves, standard_node_hash).unwrap();
        let mp = multi_proof(&tree, &[4, 5]).unwrap();
        let root = process_multi_proof(&mp, standard_node_hash).unwrap();
        assert_eq!(root, tree[0]);
    }

    #[test]
    fn multi_proof_all_leaves() {
        let leaves = test_leaves(4);
        let tree = build(&leaves, standard_node_hash).unwrap();
        let indices: Vec<usize> = (tree.len() - leaves.len()..tree.len()).collect();
        let mp = multi_proof(&tree, &indices).unwrap();
        let root = process_multi_proof(&mp, standard_node_hash).unwrap();
        assert_eq!(root, tree[0]);
    }

    #[test]
    fn multi_proof_empty_indices() {
        let leaves = test_leaves(4);
        let tree = build(&leaves, standard_node_hash).unwrap();
        let mp = multi_proof(&tree, &[]).unwrap();
        assert!(mp.leaves.is_empty());
        assert_eq!(mp.proof.len(), 1);
        assert_eq!(mp.proof[0], tree[0]);
    }

    #[test]
    fn duplicate_index_rejected() {
        let leaves = vec![[0u8; 32]; 2];
        let tree = build(&leaves, standard_node_hash).unwrap();
        let result = multi_proof(&tree, &[1, 1]);
        assert!(matches!(result, Err(Error::DuplicateIndex(1))));
    }

    #[test]
    fn proof_for_internal_node_rejected() {
        let leaves = vec![[0u8; 32]; 2];
        let tree = build(&leaves, standard_node_hash).unwrap();
        assert!(matches!(proof(&tree, 0), Err(Error::NotALeaf(0))));
    }

    #[test]
    fn invalid_trees() {
        assert!(!is_valid(&[], standard_node_hash));
        assert!(!is_valid(&[[0u8; 32]; 2], standard_node_hash));
        assert!(!is_valid(&[[0u8; 32]; 3], standard_node_hash));
    }

    #[test]
    fn render_tree() {
        let leaves = test_leaves(2);
        let tree = build(&leaves, standard_node_hash).unwrap();
        let text = render(&tree).unwrap();
        assert!(text.contains("0)"), "should contain root index");
        assert!(text.contains("0x"), "should contain hex hashes");
    }

    #[test]
    fn multi_proof_json_roundtrip() {
        let mp = MultiProof {
            leaves: vec![[0u8; 32]],
            proof: vec![[1u8; 32]],
            proof_flags: vec![true, false],
        };
        let json = MultiProofJson::from(&mp);
        let json_str = serde_json::to_string(&json).unwrap();
        assert!(json_str.contains("proofFlags"));
        let parsed: MultiProofJson = serde_json::from_str(&json_str).unwrap();
        let recovered = MultiProof::try_from(parsed).unwrap();
        assert_eq!(mp, recovered);
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
