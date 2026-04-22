//! Multi-leaf proof data structure, generation, verification and JSON DTO.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::index::{check_leaf, parent, sibling};
use crate::bytes::{Bytes32, decode_hex, encode_hex};
use crate::error::{Error, Result};
use crate::hashes::NodeHashFn;

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

/// Serde-compatible multi-proof for JSON serialization (hex strings, `camelCase`).
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
            .map(|s| decode_hex(s))
            .collect::<Result<Vec<_>>>()?;
        let proof = json
            .proof
            .iter()
            .map(|s| decode_hex(s))
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
            leaves: mp.leaves.iter().map(encode_hex).collect(),
            proof: mp.proof.iter().map(encode_hex).collect(),
            proof_flags: mp.proof_flags.clone(),
        }
    }
}

/// Generate a multi-proof for the given leaf indices.
pub(crate) fn multi_proof(tree: &[Bytes32], indices: &[usize]) -> Result<MultiProof> {
    for &i in indices {
        check_leaf(tree.len(), i)?;
    }

    let mut sorted: Vec<usize> = indices.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));

    for pair in sorted.windows(2) {
        if let [a, b] = *pair
            && a == b
        {
            return Err(Error::DuplicateIndex(a));
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
            proof_nodes.push(*tree.get(s).ok_or(Error::IndexOutOfBounds {
                index: s,
                len: tree.len(),
            })?);
        }
        queue.push_back(p);
    }

    if indices.is_empty() {
        proof_nodes.push(*tree.first().ok_or(Error::EmptyLeaves)?);
    }

    let leaves: Vec<Bytes32> = sorted
        .iter()
        .map(|&i| {
            tree.get(i).copied().ok_or(Error::IndexOutOfBounds {
                index: i,
                len: tree.len(),
            })
        })
        .collect::<Result<_>>()?;

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
        let a = stack.pop_front().ok_or(Error::MultiproofStackEmpty)?;
        let b = if flag {
            stack.pop_front().ok_or(Error::MultiproofStackEmpty)?
        } else {
            *proof_iter.next().ok_or(Error::MultiproofProofExhausted)?
        };
        stack.push_back(node_hash(&a, &b));
    }

    let remaining: usize = stack.len() + proof_iter.count();
    if remaining != 1 {
        return Err(Error::MultiproofNotConverged);
    }

    stack.pop_front().ok_or(Error::MultiproofStackEmpty)
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
    fn multi_proof_roundtrip() {
        let leaves = test_leaves(4);
        let tree = build(&leaves, standard_node_hash).unwrap();
        let mp = multi_proof(&tree, &[4, 5]).unwrap();
        let root = process_multi_proof(&mp, standard_node_hash).unwrap();
        assert_eq!(root, *tree.first().unwrap());
    }

    #[test]
    fn multi_proof_all_leaves() {
        let leaves = test_leaves(4);
        let tree = build(&leaves, standard_node_hash).unwrap();
        let indices: Vec<usize> = (tree.len() - leaves.len()..tree.len()).collect();
        let mp = multi_proof(&tree, &indices).unwrap();
        let root = process_multi_proof(&mp, standard_node_hash).unwrap();
        assert_eq!(root, *tree.first().unwrap());
    }

    #[test]
    fn multi_proof_empty_indices() {
        let leaves = test_leaves(4);
        let tree = build(&leaves, standard_node_hash).unwrap();
        let mp = multi_proof(&tree, &[]).unwrap();
        assert!(mp.leaves.is_empty());
        assert_eq!(mp.proof.len(), 1);
        assert_eq!(*mp.proof.first().unwrap(), *tree.first().unwrap());
    }

    #[test]
    fn duplicate_index_rejected() {
        let leaves = vec![[0u8; 32]; 2];
        let tree = build(&leaves, standard_node_hash).unwrap();
        let result = multi_proof(&tree, &[1, 1]);
        assert!(matches!(result, Err(Error::DuplicateIndex(1))));
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
}
