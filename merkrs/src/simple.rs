use ahash::AHashMap;
use serde::{Deserialize, Serialize};

use crate::bytes::{Bytes32, bytes_to_hex, hex_to_bytes};
use crate::error::{Error, Result};
use crate::hashes::{NodeHashFn, keccak256, standard_node_hash};
use crate::tree::{self, MultiProof};

fn leaf_hash(value: &Bytes32) -> Bytes32 {
    keccak256(value)
}

/// Serialisable snapshot of a [`SimpleMerkleTree`].
///
/// JSON field names use camelCase to stay compatible with the
/// OpenZeppelin JavaScript `simple-v1` format.
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

/// A Merkle tree over raw `[u8; 32]` values.
///
/// Leaves are single-hashed with `keccak256` before insertion.
#[derive(Debug)]
pub struct SimpleMerkleTree {
    tree: Vec<Bytes32>,
    values: Vec<Bytes32>,
    tree_indices: Vec<usize>,
    hash_lookup: AHashMap<Bytes32, usize>,
    node_hash: NodeHashFn,
    uses_custom_hash: bool,
}

impl SimpleMerkleTree {
    /// Build a new tree from raw 32-byte values.
    pub fn of(values: &[Bytes32], options: Options) -> Result<Self> {
        if values.is_empty() {
            return Err(Error::EmptyLeaves);
        }

        let node_hash_fn = options.node_hash.unwrap_or(standard_node_hash);

        let mut indexed: Vec<(usize, Bytes32)> = values
            .iter()
            .enumerate()
            .map(|(i, v)| (i, leaf_hash(v)))
            .collect();

        if options.sort_leaves {
            indexed.sort_unstable_by(|a, b| a.1.cmp(&b.1));
        }

        let leaves: Vec<Bytes32> = indexed.iter().map(|(_, h)| *h).collect();
        let tree = tree::build(&leaves, node_hash_fn)?;

        let mut tree_indices = vec![0usize; values.len()];
        for (leaf_pos, &(value_idx, _)) in indexed.iter().enumerate() {
            tree_indices[value_idx] = tree.len() - 1 - leaf_pos;
        }

        let hash_lookup = tree_indices
            .iter()
            .enumerate()
            .map(|(vi, &ti)| (tree[ti], vi))
            .collect();

        Ok(Self {
            tree,
            values: values.to_vec(),
            tree_indices,
            hash_lookup,
            node_hash: node_hash_fn,
            uses_custom_hash: options.node_hash.is_some(),
        })
    }

    /// Reconstruct a tree from a serialised snapshot.
    pub fn load(data: SimpleMerkleTreeData, node_hash: Option<NodeHashFn>) -> Result<Self> {
        if data.format != "simple-v1" {
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
            .map(|s| hex_to_bytes(s))
            .collect::<Result<_>>()?;

        let mut values = Vec::with_capacity(data.values.len());
        let mut tree_indices = Vec::with_capacity(data.values.len());
        for entry in &data.values {
            values.push(hex_to_bytes(&entry.value)?);
            tree_indices.push(entry.tree_index);
        }

        let hash_lookup = tree_indices
            .iter()
            .enumerate()
            .map(|(vi, &ti)| (tree[ti], vi))
            .collect();

        let me = Self {
            tree,
            values,
            tree_indices,
            hash_lookup,
            node_hash: node_hash_fn,
            uses_custom_hash: has_custom,
        };
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
        let hash = leaf_hash(leaf);
        tree::process_proof(&hash, proof, nh) == *root
    }

    /// Verify a multi-proof against a known root without a tree instance.
    pub fn verify_multi_proof(
        root: &Bytes32,
        mp: &MultiProof,
        node_hash: Option<NodeHashFn>,
    ) -> Result<bool> {
        let nh = node_hash.unwrap_or(standard_node_hash);
        let computed = tree::process_multi_proof(mp, nh)?;
        Ok(computed == *root)
    }

    /// The Merkle root hash.
    #[must_use]
    pub fn root(&self) -> &Bytes32 {
        &self.tree[0]
    }

    /// Number of leaves (values).
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.values.len()
    }

    /// Whether the tree has no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Get the value at the given index.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&Bytes32> {
        self.values.get(index)
    }

    /// Iterate over `(index, value)` pairs.
    pub fn entries(&self) -> impl Iterator<Item = (usize, &Bytes32)> {
        self.values.iter().enumerate()
    }

    /// Serialise to a JSON-friendly snapshot.
    #[must_use]
    pub fn dump(&self) -> SimpleMerkleTreeData {
        let tree_hex: Vec<String> = self.tree.iter().map(bytes_to_hex).collect();
        let values: Vec<ValueEntry> = self
            .values
            .iter()
            .zip(&self.tree_indices)
            .map(|(v, &ti)| ValueEntry {
                value: bytes_to_hex(v),
                tree_index: ti,
            })
            .collect();

        SimpleMerkleTreeData {
            format: "simple-v1".into(),
            tree: tree_hex,
            values,
            hash: if self.uses_custom_hash {
                Some("custom".into())
            } else {
                None
            },
        }
    }

    /// Pretty-print the tree structure.
    pub fn render(&self) -> Result<String> {
        tree::render(&self.tree)
    }

    /// Validate internal consistency.
    pub fn validate(&self) -> Result<()> {
        for (i, (val, &ti)) in self.values.iter().zip(&self.tree_indices).enumerate() {
            let expected = leaf_hash(val);
            if self.tree[ti] != expected {
                return Err(Error::ValueMismatch(i));
            }
        }
        if !tree::is_valid(&self.tree, self.node_hash) {
            return Err(Error::InvalidTree);
        }
        Ok(())
    }

    /// Look up the value-index for a given leaf value.
    pub fn leaf_lookup(&self, value: &Bytes32) -> Result<usize> {
        let hash = leaf_hash(value);
        self.hash_lookup
            .get(&hash)
            .copied()
            .ok_or(Error::LeafNotFound)
    }

    /// Generate a Merkle proof for the value at `index`.
    pub fn get_proof_by_index(&self, index: usize) -> Result<Vec<Bytes32>> {
        let len = self.values.len();
        if index >= len {
            return Err(Error::IndexOutOfBounds { index, len });
        }
        let ti = self.tree_indices[index];
        let p = tree::proof(&self.tree, ti)?;
        let root = tree::process_proof(&self.tree[ti], &p, self.node_hash);
        if root != self.tree[0] {
            return Err(Error::UnableToProve(index));
        }
        Ok(p)
    }

    /// Generate a Merkle proof for a value.
    pub fn get_proof(&self, value: &Bytes32) -> Result<Vec<Bytes32>> {
        self.get_proof_by_index(self.leaf_lookup(value)?)
    }

    /// Generate a multi-proof for multiple value indices.
    pub fn get_multi_proof_by_indices(&self, indices: &[usize]) -> Result<MultiProof> {
        let len = self.values.len();
        for &idx in indices {
            if idx >= len {
                return Err(Error::IndexOutOfBounds { index: idx, len });
            }
        }
        let tree_indices: Vec<usize> = indices.iter().map(|&i| self.tree_indices[i]).collect();
        let mp = tree::multi_proof(&self.tree, &tree_indices)?;
        let root = tree::process_multi_proof(&mp, self.node_hash)?;
        if root != self.tree[0] {
            return Err(Error::UnableToProve(0));
        }
        Ok(mp)
    }

    /// Verify a proof for a given value against this tree's root.
    #[must_use]
    pub fn verify_proof(&self, value: &Bytes32, proof: &[Bytes32]) -> bool {
        let hash = leaf_hash(value);
        tree::process_proof(&hash, proof, self.node_hash) == self.tree[0]
    }

    /// Verify a proof for the value at `index`.
    pub fn verify_proof_by_index(&self, index: usize, proof: &[Bytes32]) -> Result<bool> {
        let len = self.values.len();
        if index >= len {
            return Err(Error::IndexOutOfBounds { index, len });
        }
        let hash = leaf_hash(&self.values[index]);
        Ok(tree::process_proof(&hash, proof, self.node_hash) == self.tree[0])
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
        let tree = SimpleMerkleTree::of(&vals, Options::default()).unwrap();
        assert_eq!(tree.leaf_count(), 4);
        tree.validate().unwrap();
    }

    #[test]
    fn single_leaf() {
        let vals = test_values(1);
        let tree = SimpleMerkleTree::of(&vals, Options::default()).unwrap();
        assert_eq!(tree.leaf_count(), 1);
        tree.validate().unwrap();
    }

    #[test]
    fn proof_roundtrip() {
        let vals = test_values(8);
        let tree = SimpleMerkleTree::of(&vals, Options::default()).unwrap();
        for (i, v) in vals.iter().enumerate() {
            let p = tree.get_proof(v).unwrap();
            assert!(tree.verify_proof(v, &p), "proof failed for value {i}");
            assert!(tree.verify_proof_by_index(i, &p).unwrap());
        }
    }

    #[test]
    fn static_verify() {
        let vals = test_values(4);
        let tree = SimpleMerkleTree::of(&vals, Options::default()).unwrap();
        for v in &vals {
            let p = tree.get_proof(v).unwrap();
            assert!(SimpleMerkleTree::verify(tree.root(), v, &p, None));
        }
    }

    #[test]
    fn reject_invalid_proof() {
        let v1 = test_values(4);
        let t1 = SimpleMerkleTree::of(&v1, Options::default()).unwrap();
        let v2: Vec<Bytes32> = v1.iter().map(|v| { let mut c = *v; c[0] = 0xff; c }).collect();
        let t2 = SimpleMerkleTree::of(&v2, Options::default()).unwrap();
        let proof = t1.get_proof(&v1[0]).unwrap();
        assert!(!t2.verify_proof(&v1[0], &proof));
    }

    #[test]
    fn multi_proof() {
        let vals = test_values(4);
        let tree = SimpleMerkleTree::of(&vals, Options::default()).unwrap();
        let mp = tree.get_multi_proof_by_indices(&[0, 2]).unwrap();
        assert!(SimpleMerkleTree::verify_multi_proof(tree.root(), &mp, None).unwrap());
    }

    #[test]
    fn dump_and_load() {
        let vals = test_values(4);
        let tree = SimpleMerkleTree::of(&vals, Options::default()).unwrap();
        let data = tree.dump();
        assert_eq!(data.format, "simple-v1");
        let json = serde_json::to_string(&data).unwrap();
        let loaded_data: SimpleMerkleTreeData = serde_json::from_str(&json).unwrap();
        let loaded = SimpleMerkleTree::load(loaded_data, None).unwrap();
        assert_eq!(tree.root(), loaded.root());
        assert_eq!(tree.leaf_count(), loaded.leaf_count());
    }

    #[test]
    fn entries_match_get() {
        let vals = test_values(4);
        let tree = SimpleMerkleTree::of(&vals, Options::default()).unwrap();
        for (i, v) in tree.entries() {
            assert_eq!(Some(v), tree.get(i));
        }
        assert!(tree.get(tree.leaf_count()).is_none());
    }

    #[test]
    fn unsorted_leaves() {
        let vals = test_values(4);
        let opts = Options { sort_leaves: false, node_hash: None };
        let tree = SimpleMerkleTree::of(&vals, opts).unwrap();
        tree.validate().unwrap();
        for v in &vals {
            let p = tree.get_proof(v).unwrap();
            assert!(tree.verify_proof(v, &p));
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
        assert!(matches!(SimpleMerkleTree::load(data, None), Err(Error::UnknownFormat(_))));
    }

    #[test]
    fn out_of_bounds() {
        let vals = test_values(4);
        let tree = SimpleMerkleTree::of(&vals, Options::default()).unwrap();
        assert!(matches!(
            tree.get_proof_by_index(100),
            Err(Error::IndexOutOfBounds { .. })
        ));
    }
}
