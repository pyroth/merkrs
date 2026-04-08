//! [`SimpleMerkleTree`] — Merkle tree over raw `[u8; 32]` values.

use serde::{Deserialize, Serialize};

use crate::bytes::{Bytes32, decode_hex, encode_hex};
use crate::error::{Error, Result};
use crate::hashes::{NodeHashFn, keccak256, standard_node_hash};
use crate::merkle::{LeafHasher, MerkleTree, TreeParts};
use crate::tree::{self, MultiProof};

const FORMAT: &str = "simple-v1";

/// Leaf hashing strategy for simple trees (single `keccak256`).
#[derive(Debug, Clone, Copy)]
pub struct SimpleHasher;

impl LeafHasher for SimpleHasher {
    type Value = Bytes32;

    fn hash_leaf(&self, value: &Bytes32) -> Result<Bytes32> {
        Ok(keccak256(value))
    }
}

/// A Merkle tree over raw `[u8; 32]` values.
///
/// Leaves are single-hashed with `keccak256` before insertion.
pub type SimpleMerkleTree = MerkleTree<SimpleHasher>;

/// Serialisable snapshot of a [`SimpleMerkleTree`].
///
/// JSON field names use `camelCase` to stay compatible with the
/// `OpenZeppelin` JavaScript `simple-v1` format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimpleMerkleTreeData {
    /// Format identifier (always `"simple-v1"`).
    pub format: String,
    /// Flat tree array as hex strings (index 0 = root).
    pub tree: Vec<String>,
    /// Original values with their tree positions.
    pub values: Vec<ValueEntry>,
    /// Set to `"custom"` when a non-default node hash was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// One value stored in a [`SimpleMerkleTree`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueEntry {
    /// Hex-encoded 32-byte value.
    pub value: String,
    /// Index of this leaf's hash in the flat tree array.
    pub tree_index: usize,
}

/// Options for constructing a [`SimpleMerkleTree`].
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Whether to sort leaves by hash before building the tree.
    pub sort_leaves: bool,
    /// Custom node hashing function; defaults to `standard_node_hash`.
    pub node_hash: Option<NodeHashFn>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            sort_leaves: true,
            node_hash: None,
        }
    }
}

impl SimpleMerkleTree {
    /// Build a new tree from raw 32-byte values.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyLeaves`] when `values` is empty.
    pub fn new(values: &[Bytes32], options: Options) -> Result<Self> {
        if values.is_empty() {
            return Err(Error::EmptyLeaves);
        }

        let node_hash_fn = options.node_hash.unwrap_or(standard_node_hash);

        let mut indexed: Vec<(usize, Bytes32)> = values
            .iter()
            .enumerate()
            .map(|(i, v)| (i, keccak256(v)))
            .collect();

        if options.sort_leaves {
            indexed.sort_unstable_by_key(|a| a.1);
        }

        let leaves: Vec<Bytes32> = indexed.iter().map(|(_, h)| *h).collect();
        let tree = tree::build(&leaves, node_hash_fn)?;

        let mut tree_indices = vec![0usize; values.len()];
        for (leaf_pos, &(value_idx, _)) in indexed.iter().enumerate() {
            if let Some(slot) = tree_indices.get_mut(value_idx) {
                *slot = tree.len() - 1 - leaf_pos;
            }
        }

        Ok(Self::from_parts(TreeParts {
            hasher: SimpleHasher,
            tree,
            values: values.to_vec(),
            tree_indices,
            node_hash: node_hash_fn,
            custom_node_hash: options.node_hash.is_some(),
        }))
    }

    /// Reconstruct a tree from a serialised snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownFormat`] if the format string is unexpected, or
    /// propagates any hex-decode / validation error.
    pub fn from_data(data: SimpleMerkleTreeData, node_hash: Option<NodeHashFn>) -> Result<Self> {
        if data.format != FORMAT {
            return Err(Error::UnknownFormat(data.format));
        }

        let has_custom = data.hash.as_deref() == Some("custom");
        if node_hash.is_some() != has_custom {
            return Err(Error::UnknownFormat(
                "node_hash option does not match serialised hash field".into(),
            ));
        }

        let node_hash_fn = node_hash.unwrap_or(standard_node_hash);

        let tree: Vec<Bytes32> = data
            .tree
            .iter()
            .map(|s| decode_hex(s))
            .collect::<Result<_>>()?;

        let mut values = Vec::with_capacity(data.values.len());
        let mut tree_indices = Vec::with_capacity(data.values.len());
        for entry in &data.values {
            values.push(decode_hex(&entry.value)?);
            tree_indices.push(entry.tree_index);
        }

        let me = Self::from_parts(TreeParts {
            hasher: SimpleHasher,
            tree,
            values,
            tree_indices,
            node_hash: node_hash_fn,
            custom_node_hash: has_custom,
        });
        me.validate()?;
        Ok(me)
    }

    /// Verify a single leaf against a known root without a tree instance.
    pub fn verify(
        root: &Bytes32,
        leaf: &Bytes32,
        proof: &[Bytes32],
        node_hash: Option<NodeHashFn>,
    ) -> bool {
        let nh = node_hash.unwrap_or(standard_node_hash);
        let hash = keccak256(leaf);
        tree::process_proof(&hash, proof, nh) == *root
    }

    /// Verify a multi-proof against a known root without a tree instance.
    ///
    /// # Errors
    ///
    /// Propagates any multi-proof processing error.
    pub fn verify_multi_proof(
        root: &Bytes32,
        mp: &MultiProof,
        node_hash: Option<NodeHashFn>,
    ) -> Result<bool> {
        let nh = node_hash.unwrap_or(standard_node_hash);
        let computed = tree::process_multi_proof(mp, nh)?;
        Ok(computed == *root)
    }

    /// Serialise to a JSON-friendly snapshot.
    #[must_use]
    pub fn to_data(&self) -> SimpleMerkleTreeData {
        let tree_hex: Vec<String> = self.tree.iter().map(encode_hex).collect();
        let values: Vec<ValueEntry> = self
            .values
            .iter()
            .zip(&self.tree_indices)
            .map(|(v, &ti)| ValueEntry {
                value: encode_hex(v),
                tree_index: ti,
            })
            .collect();

        SimpleMerkleTreeData {
            format: FORMAT.into(),
            tree: tree_hex,
            values,
            hash: if self.custom_node_hash {
                Some("custom".into())
            } else {
                None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_values(count: usize) -> Vec<Bytes32> {
        (0..count)
            .map(|i| {
                let mut b = [0u8; 32];
                #[expect(clippy::cast_possible_truncation, reason = "test helper, i < 256")]
                {
                    b[31] = i as u8;
                }
                b
            })
            .collect()
    }

    #[test]
    fn basic_construction() {
        let vals = test_values(4);
        let tree = SimpleMerkleTree::new(&vals, Options::default()).unwrap();
        assert_eq!(tree.len(), 4);
        tree.validate().unwrap();
    }

    #[test]
    fn single_leaf() {
        let vals = test_values(1);
        let tree = SimpleMerkleTree::new(&vals, Options::default()).unwrap();
        assert_eq!(tree.len(), 1);
        tree.validate().unwrap();
    }

    #[test]
    fn proof_roundtrip() {
        let vals = test_values(8);
        let tree = SimpleMerkleTree::new(&vals, Options::default()).unwrap();
        for (i, v) in vals.iter().enumerate() {
            let p = tree.proof(v).unwrap();
            assert!(
                tree.verify_proof(v, &p).unwrap(),
                "proof failed for value {i}"
            );
            assert!(tree.verify_proof_by_index(i, &p).unwrap());
        }
    }

    #[test]
    fn static_verify() {
        let vals = test_values(4);
        let tree = SimpleMerkleTree::new(&vals, Options::default()).unwrap();
        for v in &vals {
            let p = tree.proof(v).unwrap();
            assert!(SimpleMerkleTree::verify(tree.root(), v, &p, None));
        }
    }

    #[test]
    fn reject_invalid_proof() {
        let v1 = test_values(4);
        let t1 = SimpleMerkleTree::new(&v1, Options::default()).unwrap();
        let v2: Vec<Bytes32> = v1
            .iter()
            .map(|v| {
                let mut c = *v;
                c[0] = 0xff;
                c
            })
            .collect();
        let t2 = SimpleMerkleTree::new(&v2, Options::default()).unwrap();
        let proof = t1.proof(v1.first().unwrap()).unwrap();
        assert!(!t2.verify_proof(v1.first().unwrap(), &proof).unwrap());
    }

    #[test]
    fn multi_proof() {
        let vals = test_values(4);
        let tree = SimpleMerkleTree::new(&vals, Options::default()).unwrap();
        let mp = tree.multi_proof_by_indices(&[0, 2]).unwrap();
        assert!(SimpleMerkleTree::verify_multi_proof(tree.root(), &mp, None).unwrap());
    }

    #[test]
    fn dump_and_load() {
        let vals = test_values(4);
        let tree = SimpleMerkleTree::new(&vals, Options::default()).unwrap();
        let data = tree.to_data();
        assert_eq!(data.format, FORMAT);
        let json = serde_json::to_string(&data).unwrap();
        let loaded_data: SimpleMerkleTreeData = serde_json::from_str(&json).unwrap();
        let loaded = SimpleMerkleTree::from_data(loaded_data, None).unwrap();
        assert_eq!(tree.root(), loaded.root());
        assert_eq!(tree.len(), loaded.len());
    }

    #[test]
    fn entries_match_get() {
        let vals = test_values(4);
        let tree = SimpleMerkleTree::new(&vals, Options::default()).unwrap();
        for (i, v) in tree.entries() {
            assert_eq!(Some(v), tree.get(i));
        }
        assert!(tree.get(tree.len()).is_none());
    }

    #[test]
    fn unsorted_leaves() {
        let vals = test_values(4);
        let opts = Options {
            sort_leaves: false,
            node_hash: None,
        };
        let tree = SimpleMerkleTree::new(&vals, opts).unwrap();
        tree.validate().unwrap();
        for v in &vals {
            let p = tree.proof(v).unwrap();
            assert!(tree.verify_proof(v, &p).unwrap());
        }
    }

    #[test]
    fn unknown_format_rejected() {
        let data = SimpleMerkleTreeData {
            format: "bad".into(),
            tree: vec![],
            values: vec![],
            hash: None,
        };
        assert!(matches!(
            SimpleMerkleTree::from_data(data, None),
            Err(Error::UnknownFormat(_))
        ));
    }

    #[test]
    fn out_of_bounds() {
        let vals = test_values(4);
        let tree = SimpleMerkleTree::new(&vals, Options::default()).unwrap();
        assert!(matches!(
            tree.proof_by_index(100),
            Err(Error::IndexOutOfBounds { .. })
        ));
    }
}
