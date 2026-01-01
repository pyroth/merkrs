use crate::bytes::{Bytes32, HexString, ToBytes32, bytes32_to_hex};
use crate::error::{MerkleTreeError, Result, invariant, validate_argument};
use crate::hashes::{NodeHashFn, default_node_hash};
use serde::{Deserialize, Serialize};

#[inline]
fn left_child_index(i: usize) -> usize {
    2 * i + 1
}

#[inline]
fn right_child_index(i: usize) -> usize {
    2 * i + 2
}

#[inline]
fn parent_index(i: usize) -> Result<usize> {
    if i == 0 {
        Err(MerkleTreeError::RootHasNoParent)
    } else {
        Ok((i - 1) / 2)
    }
}

#[inline]
fn sibling_index(i: usize) -> Result<usize> {
    if i == 0 {
        Err(MerkleTreeError::RootHasNoSiblings)
    } else if i % 2 == 1 {
        Ok(i + 1)
    } else {
        Ok(i - 1)
    }
}

#[inline]
fn is_tree_node(tree_len: usize, i: usize) -> bool {
    i < tree_len
}

#[inline]
fn is_internal_node(tree_len: usize, i: usize) -> bool {
    is_tree_node(tree_len, left_child_index(i))
}

#[inline]
fn is_leaf_node(tree_len: usize, i: usize) -> bool {
    is_tree_node(tree_len, i) && !is_internal_node(tree_len, i)
}

fn check_leaf_node(tree_len: usize, i: usize) -> Result<()> {
    if !is_leaf_node(tree_len, i) {
        Err(MerkleTreeError::NotALeaf)
    } else {
        Ok(())
    }
}

fn check_valid_merkle_node<T: ToBytes32>(node: &T) -> Result<()> {
    node.to_bytes32()?;
    Ok(())
}

pub fn make_merkle_tree(leaves: &[Bytes32], node_hash: NodeHashFn) -> Result<Vec<HexString>> {
    for leaf in leaves {
        check_valid_merkle_node(leaf)?;
    }

    validate_argument(!leaves.is_empty(), "Expected non-zero number of leaves")?;

    let tree_len = 2 * leaves.len() - 1;
    let mut tree: Vec<HexString> = vec![String::new(); tree_len];

    for (i, leaf) in leaves.iter().enumerate() {
        tree[tree_len - 1 - i] = bytes32_to_hex(leaf);
    }

    for i in (0..tree_len - leaves.len()).rev() {
        let left = tree[left_child_index(i)].to_bytes32()?;
        let right = tree[right_child_index(i)].to_bytes32()?;
        tree[i] = bytes32_to_hex(&node_hash(&left, &right));
    }

    Ok(tree)
}

pub fn make_merkle_tree_default(leaves: &[Bytes32]) -> Result<Vec<HexString>> {
    make_merkle_tree(leaves, default_node_hash)
}

pub fn get_proof(tree: &[HexString], index: usize) -> Result<Vec<HexString>> {
    check_leaf_node(tree.len(), index)?;

    let mut proof = Vec::new();
    let mut idx = index;

    while idx > 0 {
        let sib = sibling_index(idx)?;
        proof.push(tree[sib].clone());
        idx = parent_index(idx)?;
    }

    Ok(proof)
}

pub fn process_proof<T: ToBytes32>(
    leaf: &T,
    proof: &[HexString],
    node_hash: NodeHashFn,
) -> Result<HexString> {
    check_valid_merkle_node(leaf)?;
    for p in proof {
        check_valid_merkle_node(p)?;
    }

    let mut current = leaf.to_bytes32()?;
    for sibling in proof {
        let sib_bytes = sibling.to_bytes32()?;
        current = node_hash(&current, &sib_bytes);
    }

    Ok(bytes32_to_hex(&current))
}

pub fn process_proof_default<T: ToBytes32>(leaf: &T, proof: &[HexString]) -> Result<HexString> {
    process_proof(leaf, proof, default_node_hash)
}

/// A multi-proof structure for proving multiple leaves at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiProof {
    /// The leaf hashes being proven.
    pub leaves: Vec<HexString>,
    /// The proof elements.
    pub proof: Vec<HexString>,
    /// Flags indicating whether to use a leaf or proof element at each step.
    pub proof_flags: Vec<bool>,
}

pub fn get_multi_proof(tree: &[HexString], indices: &[usize]) -> Result<MultiProof> {
    for &i in indices {
        check_leaf_node(tree.len(), i)?;
    }

    let mut sorted_indices: Vec<usize> = indices.to_vec();
    sorted_indices.sort_by(|a, b| b.cmp(a));

    for i in 1..sorted_indices.len() {
        if sorted_indices[i] == sorted_indices[i - 1] {
            return Err(MerkleTreeError::DuplicatedIndex);
        }
    }

    let mut stack = sorted_indices.clone();
    let mut proof = Vec::new();
    let mut proof_flags = Vec::new();

    while !stack.is_empty() && stack[0] > 0 {
        let j = stack.remove(0);
        let s = sibling_index(j)?;
        let p = parent_index(j)?;

        if !stack.is_empty() && s == stack[0] {
            proof_flags.push(true);
            stack.remove(0);
        } else {
            proof_flags.push(false);
            proof.push(tree[s].clone());
        }
        stack.push(p);
    }

    if indices.is_empty() {
        proof.push(tree[0].clone());
    }

    let leaves: Vec<HexString> = sorted_indices.iter().map(|&i| tree[i].clone()).collect();

    Ok(MultiProof {
        leaves,
        proof,
        proof_flags,
    })
}

pub fn process_multi_proof(multiproof: &MultiProof, node_hash: NodeHashFn) -> Result<HexString> {
    for leaf in &multiproof.leaves {
        check_valid_merkle_node(leaf)?;
    }
    for p in &multiproof.proof {
        check_valid_merkle_node(p)?;
    }

    let proof_needed = multiproof.proof_flags.iter().filter(|&&b| !b).count();
    validate_argument(
        multiproof.proof.len() >= proof_needed,
        "Invalid multiproof format",
    )?;
    validate_argument(
        multiproof.leaves.len() + multiproof.proof.len() == multiproof.proof_flags.len() + 1,
        "Provided leaves and multiproof are not compatible",
    )?;

    let mut stack: Vec<Bytes32> = multiproof
        .leaves
        .iter()
        .map(|l| l.to_bytes32())
        .collect::<Result<Vec<_>>>()?;
    let mut proof: Vec<Bytes32> = multiproof
        .proof
        .iter()
        .map(|p| p.to_bytes32())
        .collect::<Result<Vec<_>>>()?;

    for &flag in &multiproof.proof_flags {
        let a = stack.remove(0);
        let b = if flag {
            stack.remove(0)
        } else {
            proof.remove(0)
        };
        stack.push(node_hash(&a, &b));
    }

    invariant(
        stack.len() + proof.len() == 1,
        "Stack and proof should have exactly one element",
    )?;

    let result = if !stack.is_empty() {
        stack.remove(0)
    } else {
        proof.remove(0)
    };

    Ok(bytes32_to_hex(&result))
}

pub fn process_multi_proof_default(multiproof: &MultiProof) -> Result<HexString> {
    process_multi_proof(multiproof, default_node_hash)
}

pub fn is_valid_merkle_tree(tree: &[HexString], node_hash: NodeHashFn) -> bool {
    if tree.is_empty() {
        return false;
    }

    for (i, node) in tree.iter().enumerate() {
        if node.to_bytes32().is_err() {
            return false;
        }

        let l = left_child_index(i);
        let r = right_child_index(i);

        if r >= tree.len() {
            if l < tree.len() {
                return false;
            }
        } else {
            let left = match tree[l].to_bytes32() {
                Ok(b) => b,
                Err(_) => return false,
            };
            let right = match tree[r].to_bytes32() {
                Ok(b) => b,
                Err(_) => return false,
            };
            let expected = node_hash(&left, &right);
            let node_bytes = match node.to_bytes32() {
                Ok(b) => b,
                Err(_) => return false,
            };
            if node_bytes != expected {
                return false;
            }
        }
    }

    true
}

pub fn is_valid_merkle_tree_default(tree: &[HexString]) -> bool {
    is_valid_merkle_tree(tree, default_node_hash)
}

pub fn render_merkle_tree(tree: &[HexString]) -> Result<String> {
    validate_argument(!tree.is_empty(), "Expected non-zero number of nodes")?;

    let mut stack: Vec<(usize, Vec<usize>)> = vec![(0, vec![])];
    let mut lines = Vec::new();

    while let Some((i, path)) = stack.pop() {
        let mut line = String::new();

        for &p in path.iter().take(path.len().saturating_sub(1)) {
            line.push_str(if p == 0 { "   " } else { "│  " });
        }

        if let Some(&last) = path.last() {
            line.push_str(if last == 0 { "└─ " } else { "├─ " });
        }

        line.push_str(&format!("{}) {}", i, &tree[i]));
        lines.push(line);

        if right_child_index(i) < tree.len() {
            stack.push((right_child_index(i), [path.clone(), vec![0]].concat()));
            stack.push((left_child_index(i), [path.clone(), vec![1]].concat()));
        }
    }

    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::keccak256;

    fn make_test_leaves(count: usize) -> Vec<Bytes32> {
        (0..count).map(|i| keccak256(&[i as u8])).collect()
    }

    #[test]
    fn test_make_merkle_tree() {
        let leaves = make_test_leaves(4);
        let tree = make_merkle_tree_default(&leaves).unwrap();
        assert_eq!(tree.len(), 7);
        assert!(is_valid_merkle_tree_default(&tree));
    }

    #[test]
    fn test_get_and_process_proof() {
        let leaves = make_test_leaves(4);
        let tree = make_merkle_tree_default(&leaves).unwrap();

        for i in 4..7 {
            let proof = get_proof(&tree, i).unwrap();
            let leaf = &tree[i];
            let root = process_proof_default(leaf, &proof).unwrap();
            assert_eq!(root, tree[0]);
        }
    }

    #[test]
    fn test_multi_proof() {
        let leaves = make_test_leaves(4);
        let tree = make_merkle_tree_default(&leaves).unwrap();

        let indices = vec![4, 5];
        let multiproof = get_multi_proof(&tree, &indices).unwrap();
        let root = process_multi_proof_default(&multiproof).unwrap();
        assert_eq!(root, tree[0]);
    }

    #[test]
    fn test_render_tree() {
        let leaves = make_test_leaves(2);
        let tree = make_merkle_tree_default(&leaves).unwrap();
        let rendered = render_merkle_tree(&tree).unwrap();
        assert!(rendered.contains("0)"));
        assert!(rendered.contains("1)"));
        assert!(rendered.contains("2)"));
    }
}
