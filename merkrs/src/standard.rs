//! [`StandardMerkleTree`] — Merkle tree over ABI-encoded Solidity values.

use serde::{Deserialize, Serialize};

use crate::abi::compute_leaf_hash;
use crate::bytes::{Bytes32, decode_hex, encode_hex};
use crate::error::{Error, Result};
use crate::hashes::standard_node_hash;
use crate::merkle::{LeafHasher, MerkleTree, TreeParts};
use crate::tree;

const FORMAT: &str = "standard-v1";

/// Leaf hashing strategy for standard trees (ABI encode + double `keccak256`).
#[derive(Debug, Clone)]
pub struct StandardHasher {
    leaf_encoding: Box<[String]>,
}

impl StandardHasher {
    /// The Solidity types used to ABI-encode each leaf.
    #[must_use]
    pub fn leaf_encoding(&self) -> &[String] {
        &self.leaf_encoding
    }
}

impl LeafHasher for StandardHasher {
    type Value = Vec<serde_json::Value>;

    fn hash_leaf(&self, value: &Self::Value) -> Result<Bytes32> {
        compute_leaf_hash(&self.leaf_encoding, value)
    }
}

/// A Merkle tree over ABI-encoded Solidity values.
///
/// Leaves are double-hashed (`keccak256(keccak256(abi.encode(...)))`) to
/// prevent second-preimage attacks, matching the `OpenZeppelin` convention.
pub type StandardMerkleTree = MerkleTree<StandardHasher>;

/// Serialisable snapshot of a [`StandardMerkleTree`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StandardMerkleTreeData {
    /// Format identifier (always `"standard-v1"`).
    pub format: String,
    /// Solidity types used to ABI-encode each leaf.
    pub leaf_encoding: Vec<String>,
    /// Flat tree array as hex strings (index 0 = root).
    pub tree: Vec<String>,
    /// Original values with their tree positions.
    pub values: Vec<ValueEntry>,
}

/// One value stored in a [`StandardMerkleTree`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueEntry {
    /// The ABI-typed values for this leaf.
    pub value: Vec<serde_json::Value>,
    /// Index of this leaf's hash in the flat tree array.
    pub tree_index: usize,
}

/// Options for constructing a [`StandardMerkleTree`].
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Whether to sort leaves by hash before building the tree.
    pub sort_leaves: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { sort_leaves: true }
    }
}

impl Options {
    /// Set the `sort_leaves` option.
    #[must_use]
    pub const fn with_sort_leaves(mut self, sort: bool) -> Self {
        self.sort_leaves = sort;
        self
    }
}

impl StandardMerkleTree {
    /// Build a tree from ABI-typed values.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyLeaves`] when `values` is empty, or
    /// propagates ABI-encoding errors.
    pub fn new(
        values: Vec<Vec<serde_json::Value>>,
        leaf_encoding: Vec<String>,
        options: Options,
    ) -> Result<Self> {
        if values.is_empty() {
            return Err(Error::EmptyLeaves);
        }

        let mut indexed: Vec<(usize, Bytes32)> = values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let hash = compute_leaf_hash(&leaf_encoding, v)?;
                Ok((i, hash))
            })
            .collect::<Result<_>>()?;

        if options.sort_leaves {
            indexed.sort_unstable_by_key(|a| a.1);
        }

        let leaves: Vec<Bytes32> = indexed.iter().map(|(_, h)| *h).collect();
        let tree = tree::build(&leaves, standard_node_hash)?;

        let mut tree_indices = vec![0usize; values.len()];
        for (leaf_pos, &(value_idx, _)) in indexed.iter().enumerate() {
            if let Some(slot) = tree_indices.get_mut(value_idx) {
                *slot = tree.len() - 1 - leaf_pos;
            }
        }

        Ok(Self::from_parts(TreeParts {
            hasher: StandardHasher {
                leaf_encoding: leaf_encoding.into_boxed_slice(),
            },
            tree,
            values,
            tree_indices,
            node_hash: standard_node_hash,
            custom_node_hash: false,
        }))
    }

    /// Reconstruct from a serialised snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownFormat`] or [`Error::MissingLeafEncoding`] on
    /// invalid input, or propagates hex-decode / validation errors.
    pub fn from_data(data: StandardMerkleTreeData) -> Result<Self> {
        if data.format != FORMAT {
            return Err(Error::UnknownFormat(data.format));
        }
        if data.leaf_encoding.is_empty() {
            return Err(Error::MissingLeafEncoding);
        }

        let tree: Vec<Bytes32> = data
            .tree
            .iter()
            .map(|s| decode_hex(s))
            .collect::<Result<_>>()?;

        let mut values = Vec::with_capacity(data.values.len());
        let mut tree_indices = Vec::with_capacity(data.values.len());
        for entry in data.values {
            tree_indices.push(entry.tree_index);
            values.push(entry.value);
        }

        let me = Self::from_parts(TreeParts {
            hasher: StandardHasher {
                leaf_encoding: data.leaf_encoding.into_boxed_slice(),
            },
            tree,
            values,
            tree_indices,
            node_hash: standard_node_hash,
            custom_node_hash: false,
        });
        me.validate()?;
        Ok(me)
    }

    /// Verify a single leaf against a known root without a tree instance.
    ///
    /// # Errors
    ///
    /// Propagates ABI-encoding errors.
    pub fn verify(
        root: &Bytes32,
        leaf_encoding: &[String],
        leaf: &[serde_json::Value],
        proof: &[Bytes32],
    ) -> Result<bool> {
        let hash = compute_leaf_hash(leaf_encoding, leaf)?;
        Ok(tree::process_proof(&hash, proof, standard_node_hash) == *root)
    }

    /// Serialise to a JSON-friendly snapshot.
    #[must_use]
    pub fn to_data(&self) -> StandardMerkleTreeData {
        let tree_hex: Vec<String> = self.tree.iter().map(encode_hex).collect();
        let values: Vec<ValueEntry> = self
            .values
            .iter()
            .zip(&self.tree_indices)
            .map(|(v, &ti)| ValueEntry {
                value: v.clone(),
                tree_index: ti,
            })
            .collect();

        StandardMerkleTreeData {
            format: FORMAT.into(),
            leaf_encoding: self.hasher.leaf_encoding().to_vec(),
            tree: tree_hex,
            values,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn airdrop_data(count: usize) -> Vec<Vec<serde_json::Value>> {
        (0..count)
            .map(|i| vec![json!(format!("0x{:040x}", i + 1)), json!((i + 1) * 100)])
            .collect()
    }

    fn encoding() -> Vec<String> {
        vec!["address".into(), "uint256".into()]
    }

    #[test]
    fn basic_construction() {
        let tree =
            StandardMerkleTree::new(airdrop_data(4), encoding(), Options::default()).unwrap();
        assert_eq!(tree.len(), 4);
        tree.validate().unwrap();
    }

    #[test]
    fn single_leaf() {
        let tree =
            StandardMerkleTree::new(airdrop_data(1), encoding(), Options::default()).unwrap();
        assert_eq!(tree.len(), 1);
        tree.validate().unwrap();
    }

    #[test]
    fn proof_roundtrip() {
        let values = airdrop_data(8);
        let tree = StandardMerkleTree::new(values.clone(), encoding(), Options::default()).unwrap();
        for (i, v) in values.iter().enumerate() {
            let p = tree.proof(v).unwrap();
            assert!(tree.verify_proof(v, &p).unwrap());
            assert!(tree.verify_proof_by_index(i, &p).unwrap());
        }
    }

    #[test]
    fn static_verify() {
        let values = airdrop_data(4);
        let enc = encoding();
        let tree =
            StandardMerkleTree::new(values.clone(), enc.clone(), Options::default()).unwrap();
        for v in &values {
            let p = tree.proof(v).unwrap();
            assert!(StandardMerkleTree::verify(tree.root(), &enc, v, &p).unwrap());
        }
    }

    #[test]
    fn reject_invalid_proof() {
        let v1 = airdrop_data(4);
        let t1 = StandardMerkleTree::new(v1.clone(), encoding(), Options::default()).unwrap();
        let v2: Vec<_> = airdrop_data(4)
            .into_iter()
            .map(|mut v| {
                if let Some(slot) = v.get_mut(1) {
                    *slot = json!(9999);
                }
                v
            })
            .collect();
        let t2 = StandardMerkleTree::new(v2, encoding(), Options::default()).unwrap();
        let proof = t1.proof(v1.first().unwrap()).unwrap();
        assert!(!t2.verify_proof(v1.first().unwrap(), &proof).unwrap());
    }

    #[test]
    fn multiproof() {
        let tree =
            StandardMerkleTree::new(airdrop_data(8), encoding(), Options::default()).unwrap();
        let mp = tree.multi_proof_by_indices(&[0, 2, 5]).unwrap();
        assert_eq!(mp.leaves.len(), 3);
    }

    #[test]
    fn dump_and_load() {
        let tree =
            StandardMerkleTree::new(airdrop_data(4), encoding(), Options::default()).unwrap();
        let data = tree.to_data();
        assert_eq!(data.format, FORMAT);
        let json_str = serde_json::to_string(&data).unwrap();
        let loaded_data: StandardMerkleTreeData = serde_json::from_str(&json_str).unwrap();
        let loaded = StandardMerkleTree::from_data(loaded_data).unwrap();
        assert_eq!(tree.root(), loaded.root());
        assert_eq!(tree.len(), loaded.len());
    }

    #[test]
    fn entries_match_get() {
        let tree =
            StandardMerkleTree::new(airdrop_data(4), encoding(), Options::default()).unwrap();
        for (i, v) in tree.entries() {
            assert_eq!(Some(v), tree.get(i));
        }
        assert!(tree.get(tree.len()).is_none());
    }

    #[test]
    fn unsorted_leaves() {
        let values = airdrop_data(4);
        let tree = StandardMerkleTree::new(
            values.clone(),
            encoding(),
            Options::default().with_sort_leaves(false),
        )
        .unwrap();
        tree.validate().unwrap();
        for v in &values {
            let p = tree.proof(v).unwrap();
            assert!(tree.verify_proof(v, &p).unwrap());
        }
    }

    #[test]
    fn various_types() {
        let values = vec![
            vec![
                json!("0x1111111111111111111111111111111111111111"),
                json!(100u64),
            ],
            vec![
                json!("0x2222222222222222222222222222222222222222"),
                json!(200u64),
            ],
        ];
        let tree = StandardMerkleTree::new(values.clone(), encoding(), Options::default()).unwrap();
        for v in &values {
            let p = tree.proof(v).unwrap();
            assert!(tree.verify_proof(v, &p).unwrap());
        }
    }

    #[test]
    fn bytes32_type() {
        let values = vec![
            vec![
                json!("0x1111111111111111111111111111111111111111111111111111111111111111"),
                json!(100u64),
            ],
            vec![
                json!("0x2222222222222222222222222222222222222222222222222222222222222222"),
                json!(200u64),
            ],
        ];
        let tree = StandardMerkleTree::new(
            values.clone(),
            vec!["bytes32".into(), "uint256".into()],
            Options::default(),
        )
        .unwrap();
        for v in &values {
            let p = tree.proof(v).unwrap();
            assert!(tree.verify_proof(v, &p).unwrap());
        }
    }

    #[test]
    fn uint_types() {
        let values = vec![
            vec![json!(100u64), json!(200u64), json!(50u64)],
            vec![json!(300u64), json!(400u64), json!(60u64)],
        ];
        let tree = StandardMerkleTree::new(
            values.clone(),
            vec!["uint256".into(), "uint128".into(), "uint64".into()],
            Options::default(),
        )
        .unwrap();
        for v in &values {
            let p = tree.proof(v).unwrap();
            assert!(tree.verify_proof(v, &p).unwrap());
        }
    }

    #[test]
    fn unknown_format_rejected() {
        let data = StandardMerkleTreeData {
            format: "bad".into(),
            leaf_encoding: vec!["uint256".into()],
            tree: vec![],
            values: vec![],
        };
        assert!(matches!(
            StandardMerkleTree::from_data(data),
            Err(Error::UnknownFormat(_))
        ));
    }

    #[test]
    fn out_of_bounds() {
        let tree =
            StandardMerkleTree::new(airdrop_data(4), encoding(), Options::default()).unwrap();
        assert!(matches!(
            tree.proof_by_index(100),
            Err(Error::IndexOutOfBounds { .. })
        ));
    }

    #[test]
    fn leaf_not_found() {
        let tree =
            StandardMerkleTree::new(airdrop_data(4), encoding(), Options::default()).unwrap();
        let bad = vec![
            json!("0x9999999999999999999999999999999999999999"),
            json!(9999),
        ];
        assert!(matches!(tree.proof(&bad), Err(Error::LeafNotFound)));
    }

    #[test]
    fn large_tree() {
        let values = airdrop_data(100);
        let tree = StandardMerkleTree::new(values.clone(), encoding(), Options::default()).unwrap();
        assert_eq!(tree.len(), 100);
        tree.validate().unwrap();
        for i in [0, 25, 50, 75, 99] {
            let v = values.get(i).unwrap();
            let p = tree.proof(v).unwrap();
            assert!(tree.verify_proof(v, &p).unwrap());
        }
    }
}
