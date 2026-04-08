//! Generic Merkle tree core and the [`LeafHasher`] trait.

use ahash::AHashMap;

use crate::bytes::Bytes32;
use crate::error::{Error, Result};
use crate::hashes::NodeHashFn;
use crate::tree::{self, MultiProof};

/// Strategy for hashing leaf values into `Bytes32` nodes.
pub trait LeafHasher {
    /// The value type stored in the tree.
    type Value: Clone;

    /// Hash a value into its leaf node representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be hashed (e.g. ABI encoding failure).
    fn hash_leaf(&self, value: &Self::Value) -> Result<Bytes32>;
}

/// A generic Merkle tree parameterised by a [`LeafHasher`].
///
/// Use [`SimpleMerkleTree`](crate::SimpleMerkleTree) or
/// [`StandardMerkleTree`](crate::StandardMerkleTree) for concrete instantiations.
pub struct MerkleTree<H: LeafHasher> {
    pub(crate) hasher: H,
    pub(crate) tree: Vec<Bytes32>,
    pub(crate) values: Vec<H::Value>,
    pub(crate) tree_indices: Vec<usize>,
    hash_lookup: AHashMap<Bytes32, usize>,
    pub(crate) node_hash: NodeHashFn,
    pub(crate) custom_node_hash: bool,
}

impl<H: LeafHasher + std::fmt::Debug> std::fmt::Debug for MerkleTree<H>
where
    H::Value: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MerkleTree")
            .field("hasher", &self.hasher)
            .field("tree", &self.tree)
            .field("values", &self.values)
            .field("tree_indices", &self.tree_indices)
            .field("hash_lookup", &self.hash_lookup)
            .finish_non_exhaustive()
    }
}

/// Pre-computed components for assembling a [`MerkleTree`].
pub(crate) struct TreeParts<H: LeafHasher> {
    pub hasher: H,
    pub tree: Vec<Bytes32>,
    pub values: Vec<H::Value>,
    pub tree_indices: Vec<usize>,
    pub node_hash: NodeHashFn,
    pub custom_node_hash: bool,
}

impl<H: LeafHasher + std::fmt::Debug> MerkleTree<H>
where
    H::Value: std::fmt::Debug,
{
    /// Assemble a `MerkleTree` from pre-computed [`TreeParts`].
    pub(crate) fn from_parts(parts: TreeParts<H>) -> Self {
        let hash_lookup = parts
            .tree_indices
            .iter()
            .enumerate()
            .filter_map(|(vi, &ti)| parts.tree.get(ti).map(|h| (*h, vi)))
            .collect();
        Self {
            hasher: parts.hasher,
            tree: parts.tree,
            values: parts.values,
            tree_indices: parts.tree_indices,
            hash_lookup,
            node_hash: parts.node_hash,
            custom_node_hash: parts.custom_node_hash,
        }
    }

    /// The Merkle root hash.
    #[must_use]
    pub fn root(&self) -> &Bytes32 {
        static ZERO: Bytes32 = [0u8; 32];
        debug_assert!(!self.tree.is_empty(), "tree is never empty");
        self.tree.first().unwrap_or(&ZERO)
    }

    /// Number of leaves (values).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the tree has no values.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Get the value at the given index.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&H::Value> {
        self.values.get(index)
    }

    /// Iterate over `(index, value)` pairs.
    pub fn entries(&self) -> impl Iterator<Item = (usize, &H::Value)> {
        self.values.iter().enumerate()
    }

    /// Pretty-print the tree structure.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyLeaves`] if the tree is empty.
    pub fn render(&self) -> Result<String> {
        tree::render(&self.tree)
    }

    /// Validate internal consistency.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ValueMismatch`] or [`Error::InvalidTree`] on inconsistency.
    pub fn validate(&self) -> Result<()> {
        for (i, (val, &ti)) in self.values.iter().zip(&self.tree_indices).enumerate() {
            let expected = self.hasher.hash_leaf(val)?;
            let actual = self.tree.get(ti).ok_or(Error::IndexOutOfBounds {
                index: ti,
                len: self.tree.len(),
            })?;
            if *actual != expected {
                return Err(Error::ValueMismatch(i));
            }
        }
        if !tree::is_valid(&self.tree, self.node_hash) {
            return Err(Error::InvalidTree);
        }
        Ok(())
    }

    /// Look up the value-index for a given leaf value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LeafNotFound`] if the value is not in the tree.
    pub fn leaf_lookup(&self, value: &H::Value) -> Result<usize> {
        let hash = self.hasher.hash_leaf(value)?;
        self.hash_lookup
            .get(&hash)
            .copied()
            .ok_or(Error::LeafNotFound)
    }

    /// Generate a Merkle proof for the value at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IndexOutOfBounds`] or [`Error::UnableToProve`] on failure.
    pub fn proof_by_index(&self, index: usize) -> Result<Vec<Bytes32>> {
        let len = self.values.len();
        let &ti = self
            .tree_indices
            .get(index)
            .ok_or(Error::IndexOutOfBounds { index, len })?;
        let p = tree::proof(&self.tree, ti)?;
        let node = self.tree.get(ti).ok_or(Error::IndexOutOfBounds {
            index: ti,
            len: self.tree.len(),
        })?;
        let root = tree::process_proof(node, &p, self.node_hash);
        if root != *self.root() {
            return Err(Error::UnableToProve(index));
        }
        Ok(p)
    }

    /// Generate a Merkle proof for a value.
    ///
    /// # Errors
    ///
    /// Propagates lookup or proof-generation errors.
    pub fn proof(&self, value: &H::Value) -> Result<Vec<Bytes32>> {
        self.proof_by_index(self.leaf_lookup(value)?)
    }

    /// Generate a multi-proof for multiple value indices.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IndexOutOfBounds`] or [`Error::UnableToProve`] on failure.
    pub fn multi_proof_by_indices(&self, indices: &[usize]) -> Result<MultiProof> {
        let len = self.tree_indices.len();
        let tree_indices: Vec<usize> = indices
            .iter()
            .map(|&i| {
                self.tree_indices
                    .get(i)
                    .copied()
                    .ok_or(Error::IndexOutOfBounds { index: i, len })
            })
            .collect::<Result<_>>()?;
        let mp = tree::multi_proof(&self.tree, &tree_indices)?;
        let root = tree::process_multi_proof(&mp, self.node_hash)?;
        if root != *self.root() {
            return Err(Error::UnableToProve(0));
        }
        Ok(mp)
    }

    /// Verify a proof for a given value against this tree's root.
    ///
    /// # Errors
    ///
    /// Propagates leaf-hashing errors.
    pub fn verify_proof(&self, value: &H::Value, proof: &[Bytes32]) -> Result<bool> {
        let hash = self.hasher.hash_leaf(value)?;
        Ok(tree::process_proof(&hash, proof, self.node_hash) == *self.root())
    }

    /// Verify a proof for the value at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IndexOutOfBounds`] if `index >= leaf_count()`.
    pub fn verify_proof_by_index(&self, index: usize, proof: &[Bytes32]) -> Result<bool> {
        let val = self.values.get(index).ok_or(Error::IndexOutOfBounds {
            index,
            len: self.values.len(),
        })?;
        let hash = self.hasher.hash_leaf(val)?;
        Ok(tree::process_proof(&hash, proof, self.node_hash) == *self.root())
    }
}

impl<H: LeafHasher + std::fmt::Debug> std::fmt::Display for MerkleTree<H>
where
    H::Value: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match tree::render(&self.tree) {
            Ok(s) => f.write_str(&s),
            Err(e) => write!(f, "<render error: {e}>"),
        }
    }
}
