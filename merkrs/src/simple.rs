use crate::bytes::{Bytes32, HexString, ToBytes32, bytes32_to_hex, compare_bytes32};
use crate::core::{
    MultiProof, get_multi_proof, get_proof, is_valid_merkle_tree, make_merkle_tree,
    process_multi_proof, process_proof, render_merkle_tree,
};
use crate::error::{MerkleTreeError, Result, invariant, validate_argument};
use crate::hashes::{NodeHashFn, default_node_hash, keccak256};
use crate::options::MerkleTreeOptions;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn format_leaf(value: &Bytes32) -> Bytes32 {
    let mut padded = [0u8; 32];
    padded.copy_from_slice(value);
    keccak256(&padded)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimpleMerkleTreeData {
    pub format: String,
    pub tree: Vec<HexString>,
    pub values: Vec<SimpleValueEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimpleValueEntry {
    pub value: HexString,
    pub tree_index: usize,
}

pub struct SimpleMerkleTreeOptions {
    pub sort_leaves: bool,
    pub node_hash: Option<NodeHashFn>,
}

impl Default for SimpleMerkleTreeOptions {
    fn default() -> Self {
        Self {
            sort_leaves: true,
            node_hash: None,
        }
    }
}

impl From<MerkleTreeOptions> for SimpleMerkleTreeOptions {
    fn from(opts: MerkleTreeOptions) -> Self {
        Self {
            sort_leaves: opts.sort_leaves,
            node_hash: None,
        }
    }
}

pub struct SimpleMerkleTree {
    tree: Vec<HexString>,
    values: Vec<SimpleValueEntry>,
    hash_lookup: HashMap<HexString, usize>,
    node_hash: NodeHashFn,
    uses_custom_hash: bool,
}

impl SimpleMerkleTree {
    fn new(
        tree: Vec<HexString>,
        values: Vec<SimpleValueEntry>,
        node_hash: Option<NodeHashFn>,
    ) -> Self {
        let hash_lookup: HashMap<HexString, usize> = values
            .iter()
            .enumerate()
            .map(|(value_index, entry)| (tree[entry.tree_index].clone(), value_index))
            .collect();

        let uses_custom_hash = node_hash.is_some();
        let node_hash = node_hash.unwrap_or(default_node_hash);

        Self {
            tree,
            values,
            hash_lookup,
            node_hash,
            uses_custom_hash,
        }
    }

    pub fn of<T: ToBytes32>(values: &[T], options: SimpleMerkleTreeOptions) -> Result<Self> {
        let bytes_values: Result<Vec<Bytes32>> = values.iter().map(|v| v.to_bytes32()).collect();
        let bytes_values = bytes_values?;

        validate_argument(
            !bytes_values.is_empty(),
            "Expected non-zero number of leaves",
        )?;

        let mut hashed_values: Vec<(usize, Bytes32)> = bytes_values
            .iter()
            .enumerate()
            .map(|(i, v)| (i, format_leaf(v)))
            .collect();

        if options.sort_leaves {
            hashed_values.sort_by(|a, b| compare_bytes32(&a.1, &b.1));
        }

        let leaves: Vec<Bytes32> = hashed_values.iter().map(|(_, h)| *h).collect();
        let node_hash_fn = options.node_hash.unwrap_or(default_node_hash);
        let tree = make_merkle_tree(&leaves, node_hash_fn)?;

        let mut indexed_values: Vec<SimpleValueEntry> = bytes_values
            .iter()
            .map(|v| SimpleValueEntry {
                value: bytes32_to_hex(v),
                tree_index: 0,
            })
            .collect();

        for (leaf_index, (value_index, _)) in hashed_values.iter().enumerate() {
            indexed_values[*value_index].tree_index = tree.len() - leaf_index - 1;
        }

        Ok(Self::new(tree, indexed_values, options.node_hash))
    }

    pub fn load(data: SimpleMerkleTreeData, node_hash: Option<NodeHashFn>) -> Result<Self> {
        validate_argument(
            data.format == "simple-v1",
            format!("Unknown format '{}'", data.format),
        )?;

        let has_custom = data.hash.as_deref() == Some("custom");
        validate_argument(
            node_hash.is_some() == has_custom,
            if node_hash.is_some() {
                "Data does not expect a custom node hashing function"
            } else {
                "Data expects a custom node hashing function"
            },
        )?;

        let tree = Self::new(data.tree, data.values, node_hash);
        tree.validate()?;
        Ok(tree)
    }

    pub fn verify<T: ToBytes32>(
        root: &str,
        leaf: &T,
        proof: &[HexString],
        node_hash: Option<NodeHashFn>,
    ) -> Result<bool> {
        let leaf_bytes = leaf.to_bytes32()?;
        let leaf_hash = format_leaf(&leaf_bytes);
        let node_hash_fn = node_hash.unwrap_or(default_node_hash);
        let computed_root = process_proof(&leaf_hash, proof, node_hash_fn)?;
        Ok(root == computed_root)
    }

    pub fn verify_multi_proof(
        root: &str,
        multiproof: &MultiProof,
        node_hash: Option<NodeHashFn>,
    ) -> Result<bool> {
        let node_hash_fn = node_hash.unwrap_or(default_node_hash);
        let computed_root = process_multi_proof(multiproof, node_hash_fn)?;
        Ok(root == computed_root)
    }

    pub fn root(&self) -> &HexString {
        &self.tree[0]
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn at(&self, index: usize) -> Option<&HexString> {
        self.values.get(index).map(|e| &e.value)
    }

    pub fn dump(&self) -> SimpleMerkleTreeData {
        SimpleMerkleTreeData {
            format: "simple-v1".to_string(),
            tree: self.tree.clone(),
            values: self.values.clone(),
            hash: if self.uses_custom_hash {
                Some("custom".to_string())
            } else {
                None
            },
        }
    }

    pub fn render(&self) -> Result<String> {
        render_merkle_tree(&self.tree)
    }

    pub fn entries(&self) -> impl Iterator<Item = (usize, &HexString)> {
        self.values.iter().enumerate().map(|(i, e)| (i, &e.value))
    }

    pub fn validate(&self) -> Result<()> {
        for (i, entry) in self.values.iter().enumerate() {
            self.validate_value_at(i, entry)?;
        }
        invariant(
            is_valid_merkle_tree(&self.tree, self.node_hash),
            "Merkle tree is invalid",
        )?;
        Ok(())
    }

    fn validate_value_at(&self, _index: usize, entry: &SimpleValueEntry) -> Result<()> {
        let value_bytes = entry.value.to_bytes32()?;
        let computed_hash = format_leaf(&value_bytes);
        let stored_hash = self.tree[entry.tree_index].to_bytes32()?;
        invariant(
            computed_hash == stored_hash,
            "Merkle tree does not contain the expected value",
        )?;
        Ok(())
    }

    pub fn leaf_hash<T: ToBytes32>(&self, leaf: &T) -> Result<HexString> {
        let leaf_bytes = leaf.to_bytes32()?;
        let hash = format_leaf(&leaf_bytes);
        Ok(bytes32_to_hex(&hash))
    }

    pub fn leaf_lookup<T: ToBytes32>(&self, leaf: &T) -> Result<usize> {
        let hash = self.leaf_hash(leaf)?;
        self.hash_lookup
            .get(&hash)
            .copied()
            .ok_or(MerkleTreeError::LeafNotInTree)
    }

    pub fn get_proof_by_index(&self, index: usize) -> Result<Vec<HexString>> {
        validate_argument(index < self.values.len(), "Index out of bounds")?;
        let entry = &self.values[index];
        self.validate_value_at(index, entry)?;
        let proof = get_proof(&self.tree, entry.tree_index)?;
        let leaf_hash = &self.tree[entry.tree_index];
        invariant(
            self.verify_internal(leaf_hash, &proof)?,
            "Unable to prove value",
        )?;
        Ok(proof)
    }

    pub fn get_proof<T: ToBytes32>(&self, leaf: &T) -> Result<Vec<HexString>> {
        let index = self.leaf_lookup(leaf)?;
        self.get_proof_by_index(index)
    }

    pub fn get_multi_proof_by_indices(&self, indices: &[usize]) -> Result<MultiProof> {
        for &idx in indices {
            validate_argument(idx < self.values.len(), "Index out of bounds")?;
            let entry = &self.values[idx];
            self.validate_value_at(idx, entry)?;
        }

        let tree_indices: Vec<usize> = indices.iter().map(|&i| self.values[i].tree_index).collect();

        let proof = get_multi_proof(&self.tree, &tree_indices)?;

        invariant(
            self.verify_multi_proof_internal(&proof)?,
            "Unable to prove values",
        )?;

        Ok(proof)
    }

    pub fn verify_proof<T: ToBytes32>(&self, leaf: &T, proof: &[HexString]) -> Result<bool> {
        let leaf_hash = self.leaf_hash(leaf)?;
        self.verify_internal(&leaf_hash, proof)
    }

    pub fn verify_proof_by_index(&self, index: usize, proof: &[HexString]) -> Result<bool> {
        validate_argument(index < self.values.len(), "Index out of bounds")?;
        let leaf_hash = self.leaf_hash(&self.values[index].value)?;
        self.verify_internal(&leaf_hash, proof)
    }

    fn verify_internal(&self, leaf_hash: &HexString, proof: &[HexString]) -> Result<bool> {
        let root = process_proof(leaf_hash, proof, self.node_hash)?;
        Ok(&root == self.root())
    }

    fn verify_multi_proof_internal(&self, multiproof: &MultiProof) -> Result<bool> {
        let root = process_multi_proof(multiproof, self.node_hash)?;
        Ok(&root == self.root())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::hex_to_bytes32;
    use crate::error::MerkleTreeError;

    const ZERO: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

    fn make_test_values(count: usize) -> Vec<Bytes32> {
        (0..count)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = i as u8;
                bytes
            })
            .collect()
    }

    #[test]
    fn test_simple_merkle_tree_basic() {
        let values = make_test_values(4);
        let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

        assert_eq!(tree.len(), 4);
        assert!(!tree.root().is_empty());
        tree.validate().unwrap();
    }

    #[test]
    fn test_simple_tree_single_leaf() {
        let values = make_test_values(1);
        let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

        assert_eq!(tree.len(), 1);
        tree.validate().unwrap();
    }

    #[test]
    fn test_proof_verification() {
        let values = make_test_values(4);
        let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

        for (i, value) in values.iter().enumerate() {
            let proof = tree.get_proof(value).unwrap();
            assert!(tree.verify_proof(value, &proof).unwrap());
            assert!(tree.verify_proof_by_index(i, &proof).unwrap());
        }
    }

    #[test]
    fn test_proof_all_leaves() {
        let values = make_test_values(8);
        let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

        for (i, value) in values.iter().enumerate() {
            let proof = tree.get_proof(value).unwrap();
            assert!(tree.verify_proof(value, &proof).unwrap());
            assert!(tree.verify_proof_by_index(i, &proof).unwrap());
        }
    }

    #[test]
    fn test_static_verify() {
        let values = make_test_values(4);
        let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

        for value in &values {
            let proof = tree.get_proof(value).unwrap();
            let verified = SimpleMerkleTree::verify(tree.root(), value, &proof, None).unwrap();
            assert!(verified);
        }
    }

    #[test]
    fn test_reject_invalid_proof() {
        let values1 = make_test_values(4);
        let tree1 = SimpleMerkleTree::of(&values1, SimpleMerkleTreeOptions::default()).unwrap();

        let values2 = make_test_values(4)
            .into_iter()
            .map(|mut v| {
                v[0] = 0xff;
                v
            })
            .collect::<Vec<_>>();
        let tree2 = SimpleMerkleTree::of(&values2, SimpleMerkleTreeOptions::default()).unwrap();

        let proof = tree1.get_proof(&values1[0]).unwrap();
        let verified = tree2.verify_proof(&values1[0], &proof).unwrap();
        assert!(!verified);
    }

    #[test]
    fn test_multi_proof() {
        let values = make_test_values(4);
        let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

        let indices = vec![0, 2];
        let multiproof = tree.get_multi_proof_by_indices(&indices).unwrap();

        let result = SimpleMerkleTree::verify_multi_proof(tree.root(), &multiproof, None).unwrap();
        assert!(result);
    }

    #[test]
    fn test_multiproof_larger() {
        let values = make_test_values(8);
        let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

        let indices = vec![0, 2, 5];
        let multiproof = tree.get_multi_proof_by_indices(&indices).unwrap();

        let verified =
            SimpleMerkleTree::verify_multi_proof(tree.root(), &multiproof, None).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_dump_and_load() {
        let values = make_test_values(4);
        let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

        let data = tree.dump();
        assert_eq!(data.format, "simple-v1");
        assert!(data.hash.is_none());

        let json_str = serde_json::to_string(&data).unwrap();
        let loaded_data: SimpleMerkleTreeData = serde_json::from_str(&json_str).unwrap();
        let loaded_tree = SimpleMerkleTree::load(loaded_data, None).unwrap();

        assert_eq!(tree.root(), loaded_tree.root());
        assert_eq!(tree.len(), loaded_tree.len());
        assert_eq!(tree.render().unwrap(), loaded_tree.render().unwrap());
    }

    #[test]
    fn test_entries() {
        let values = make_test_values(4);
        let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

        for (index, value) in tree.entries() {
            assert_eq!(value, tree.at(index).unwrap());
        }
        assert!(tree.at(tree.len()).is_none());
    }

    #[test]
    fn test_unsorted_leaves() {
        let values = make_test_values(4);
        let options = SimpleMerkleTreeOptions {
            sort_leaves: false,
            node_hash: None,
        };
        let tree = SimpleMerkleTree::of(&values, options).unwrap();
        tree.validate().unwrap();

        for value in &values {
            let proof = tree.get_proof(value).unwrap();
            assert!(tree.verify_proof(value, &proof).unwrap());
        }
    }

    #[test]
    fn test_hex_values() {
        let values: Vec<Bytes32> = vec![
            hex_to_bytes32("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            hex_to_bytes32("0x0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap(),
            hex_to_bytes32("0x0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap(),
            hex_to_bytes32("0x0000000000000000000000000000000000000000000000000000000000000004")
                .unwrap(),
        ];

        let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

        for value in &values {
            let proof = tree.get_proof(value).unwrap();
            assert!(tree.verify_proof(value, &proof).unwrap());
        }
    }

    #[test]
    fn test_reject_unknown_format() {
        let data = SimpleMerkleTreeData {
            format: "nonstandard".to_string(),
            tree: vec![],
            values: vec![],
            hash: None,
        };
        let result = SimpleMerkleTree::load(data, None);
        assert!(matches!(result, Err(MerkleTreeError::InvalidArgument(_))));
    }

    #[test]
    fn test_reject_wrong_format() {
        let data = SimpleMerkleTreeData {
            format: "standard-v1".to_string(),
            tree: vec![],
            values: vec![],
            hash: None,
        };
        let result = SimpleMerkleTree::load(data, None);
        assert!(matches!(result, Err(MerkleTreeError::InvalidArgument(_))));
    }

    #[test]
    fn test_reject_malformed_dump() {
        let data = SimpleMerkleTreeData {
            format: "simple-v1".to_string(),
            tree: vec![ZERO.to_string()],
            values: vec![SimpleValueEntry {
                value: "0x0000000000000000000000000000000000000000000000000000000000000001"
                    .to_string(),
                tree_index: 0,
            }],
            hash: None,
        };
        let result = SimpleMerkleTree::load(data, None);
        assert!(matches!(result, Err(MerkleTreeError::Invariant(_))));
    }

    #[test]
    fn test_reject_invalid_tree_structure() {
        let data = SimpleMerkleTreeData {
            format: "simple-v1".to_string(),
            tree: vec![ZERO.to_string(), ZERO.to_string(), ZERO.to_string()],
            values: vec![SimpleValueEntry {
                value: ZERO.to_string(),
                tree_index: 2,
            }],
            hash: None,
        };
        let result = SimpleMerkleTree::load(data, None);
        assert!(matches!(result, Err(MerkleTreeError::Invariant(_))));
    }

    #[test]
    fn test_out_of_bounds() {
        let values = make_test_values(4);
        let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

        let result = tree.get_proof_by_index(100);
        assert!(matches!(result, Err(MerkleTreeError::InvalidArgument(_))));
    }
}
