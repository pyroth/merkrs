use crate::bytes::{Bytes32, HexString, ToBytes32, bytes32_to_hex, compare_bytes32};
use crate::core::{
    MultiProof, get_multi_proof, get_proof, is_valid_merkle_tree_default, make_merkle_tree_default,
    process_multi_proof_default, process_proof_default, render_merkle_tree,
};
use crate::error::{MerkleTreeError, Result, invariant, validate_argument};
use crate::hashes::standard_leaf_hash;
use crate::options::MerkleTreeOptions;
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StandardMerkleTreeData {
    pub format: String,
    pub leaf_encoding: Vec<String>,
    pub tree: Vec<HexString>,
    pub values: Vec<ValueEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueEntry {
    pub value: Vec<serde_json::Value>,
    pub tree_index: usize,
}

pub struct StandardMerkleTree {
    tree: Vec<HexString>,
    values: Vec<ValueEntry>,
    leaf_encoding: Vec<String>,
    hash_lookup: HashMap<HexString, usize>,
}

impl StandardMerkleTree {
    fn new(tree: Vec<HexString>, values: Vec<ValueEntry>, leaf_encoding: Vec<String>) -> Self {
        let hash_lookup: HashMap<HexString, usize> = values
            .iter()
            .enumerate()
            .map(|(value_index, entry)| (tree[entry.tree_index].clone(), value_index))
            .collect();

        Self {
            tree,
            values,
            leaf_encoding,
            hash_lookup,
        }
    }

    pub fn of(
        values: Vec<Vec<serde_json::Value>>,
        leaf_encoding: Vec<String>,
        options: MerkleTreeOptions,
    ) -> Result<Self> {
        validate_argument(!values.is_empty(), "Expected non-zero number of leaves")?;

        let hashed_values: Result<Vec<(usize, Bytes32)>> = values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let hash = Self::compute_leaf_hash(&leaf_encoding, v)?;
                Ok((i, hash))
            })
            .collect();
        let mut hashed_values = hashed_values?;

        if options.sort_leaves {
            hashed_values.sort_by(|a, b| compare_bytes32(&a.1, &b.1));
        }

        let leaves: Vec<Bytes32> = hashed_values.iter().map(|(_, h)| *h).collect();
        let tree = make_merkle_tree_default(&leaves)?;

        let mut indexed_values: Vec<ValueEntry> = values
            .into_iter()
            .map(|value| ValueEntry {
                value,
                tree_index: 0,
            })
            .collect();

        for (leaf_index, (value_index, _)) in hashed_values.iter().enumerate() {
            indexed_values[*value_index].tree_index = tree.len() - leaf_index - 1;
        }

        Ok(Self::new(tree, indexed_values, leaf_encoding))
    }

    pub fn load(data: StandardMerkleTreeData) -> Result<Self> {
        validate_argument(
            data.format == "standard-v1",
            format!("Unknown format '{}'", data.format),
        )?;
        validate_argument(!data.leaf_encoding.is_empty(), "Expected leaf encoding")?;

        let tree = Self::new(data.tree, data.values, data.leaf_encoding);
        tree.validate()?;
        Ok(tree)
    }

    pub fn verify(
        root: &str,
        leaf_encoding: &[String],
        leaf: &[serde_json::Value],
        proof: &[HexString],
    ) -> Result<bool> {
        let leaf_hash = Self::compute_leaf_hash(leaf_encoding, leaf)?;
        let computed_root = process_proof_default(&leaf_hash, proof)?;
        Ok(root == computed_root)
    }

    pub fn verify_multi_proof(
        root: &str,
        leaf_encoding: &[String],
        leaves: &[Vec<serde_json::Value>],
        proof: &[HexString],
        proof_flags: &[bool],
    ) -> Result<bool> {
        let leaf_hashes: Result<Vec<HexString>> = leaves
            .iter()
            .map(|leaf| {
                let hash = Self::compute_leaf_hash(leaf_encoding, leaf)?;
                Ok(bytes32_to_hex(&hash))
            })
            .collect();
        let leaf_hashes = leaf_hashes?;

        let multiproof = MultiProof {
            leaves: leaf_hashes,
            proof: proof.to_vec(),
            proof_flags: proof_flags.to_vec(),
        };

        let computed_root = process_multi_proof_default(&multiproof)?;
        Ok(root == computed_root)
    }

    fn compute_leaf_hash(leaf_encoding: &[String], value: &[serde_json::Value]) -> Result<Bytes32> {
        let encoded = encode_leaf(leaf_encoding, value)?;
        Ok(standard_leaf_hash(&encoded))
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

    pub fn at(&self, index: usize) -> Option<&Vec<serde_json::Value>> {
        self.values.get(index).map(|e| &e.value)
    }

    pub fn dump(&self) -> StandardMerkleTreeData {
        StandardMerkleTreeData {
            format: "standard-v1".to_string(),
            leaf_encoding: self.leaf_encoding.clone(),
            tree: self.tree.clone(),
            values: self.values.clone(),
        }
    }

    pub fn render(&self) -> Result<String> {
        render_merkle_tree(&self.tree)
    }

    pub fn entries(&self) -> impl Iterator<Item = (usize, &Vec<serde_json::Value>)> {
        self.values.iter().enumerate().map(|(i, e)| (i, &e.value))
    }

    pub fn validate(&self) -> Result<()> {
        for (i, entry) in self.values.iter().enumerate() {
            self.validate_value_at(i, entry)?;
        }
        invariant(
            is_valid_merkle_tree_default(&self.tree),
            "Merkle tree is invalid",
        )?;
        Ok(())
    }

    fn validate_value_at(&self, _index: usize, entry: &ValueEntry) -> Result<()> {
        let computed_hash = Self::compute_leaf_hash(&self.leaf_encoding, &entry.value)?;
        let stored_hash = self.tree[entry.tree_index].to_bytes32()?;
        invariant(
            computed_hash == stored_hash,
            "Merkle tree does not contain the expected value",
        )?;
        Ok(())
    }

    pub fn leaf_hash(&self, leaf: &[serde_json::Value]) -> Result<HexString> {
        let hash = Self::compute_leaf_hash(&self.leaf_encoding, leaf)?;
        Ok(bytes32_to_hex(&hash))
    }

    pub fn leaf_lookup(&self, leaf: &[serde_json::Value]) -> Result<usize> {
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

    pub fn get_proof(&self, leaf: &[serde_json::Value]) -> Result<Vec<HexString>> {
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

    pub fn verify_proof(&self, leaf: &[serde_json::Value], proof: &[HexString]) -> Result<bool> {
        let leaf_hash = self.leaf_hash(leaf)?;
        self.verify_internal(&leaf_hash, proof)
    }

    pub fn verify_proof_by_index(&self, index: usize, proof: &[HexString]) -> Result<bool> {
        validate_argument(index < self.values.len(), "Index out of bounds")?;
        let leaf_hash = self.leaf_hash(&self.values[index].value)?;
        self.verify_internal(&leaf_hash, proof)
    }

    fn verify_internal(&self, leaf_hash: &HexString, proof: &[HexString]) -> Result<bool> {
        let root = process_proof_default(leaf_hash, proof)?;
        Ok(&root == self.root())
    }

    fn verify_multi_proof_internal(&self, multiproof: &MultiProof) -> Result<bool> {
        let root = process_multi_proof_default(multiproof)?;
        Ok(&root == self.root())
    }
}

fn encode_leaf(types: &[String], values: &[serde_json::Value]) -> Result<Vec<u8>> {
    if types.len() != values.len() {
        return Err(MerkleTreeError::AbiEncode(
            "Types and values length mismatch".to_string(),
        ));
    }

    let mut encoded = Vec::new();

    for (sol_type, value) in types.iter().zip(values.iter()) {
        let bytes = encode_single_value(sol_type, value)?;
        encoded.extend(bytes);
    }

    Ok(encoded)
}

fn encode_single_value(sol_type: &str, value: &serde_json::Value) -> Result<Vec<u8>> {
    match sol_type {
        "address" => {
            let s = value
                .as_str()
                .ok_or_else(|| MerkleTreeError::AbiEncode("Expected string for address".into()))?;
            let addr: alloy_primitives::Address = s
                .parse()
                .map_err(|e| MerkleTreeError::AbiEncode(format!("Invalid address: {}", e)))?;
            Ok(addr.abi_encode())
        }
        "uint256" => {
            let uint = parse_uint256(value)?;
            Ok(uint.abi_encode())
        }
        "uint128" => {
            let uint: u128 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(uint).abi_encode())
        }
        "uint64" => {
            let uint: u64 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(uint).abi_encode())
        }
        "uint32" => {
            let uint: u32 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(uint).abi_encode())
        }
        "uint16" => {
            let uint: u16 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(uint).abi_encode())
        }
        "uint8" => {
            let uint: u8 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(uint).abi_encode())
        }
        "int256" => {
            let int = parse_int256(value)?;
            Ok(int.abi_encode())
        }
        "bytes32" => {
            let s = value
                .as_str()
                .ok_or_else(|| MerkleTreeError::AbiEncode("Expected string for bytes32".into()))?;
            let b32: alloy_primitives::B256 = s
                .parse()
                .map_err(|e| MerkleTreeError::AbiEncode(format!("Invalid bytes32: {}", e)))?;
            Ok(b32.abi_encode())
        }
        "bytes" => {
            let s = value
                .as_str()
                .ok_or_else(|| MerkleTreeError::AbiEncode("Expected string for bytes".into()))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s)
                .map_err(|e| MerkleTreeError::AbiEncode(format!("Invalid hex: {}", e)))?;
            Ok(alloy_primitives::Bytes::from(bytes).abi_encode())
        }
        "bool" => {
            let b = value
                .as_bool()
                .ok_or_else(|| MerkleTreeError::AbiEncode("Expected bool".into()))?;
            let val = if b {
                alloy_primitives::U256::from(1)
            } else {
                alloy_primitives::U256::ZERO
            };
            Ok(val.abi_encode())
        }
        "string" => {
            let s = value
                .as_str()
                .ok_or_else(|| MerkleTreeError::AbiEncode("Expected string".into()))?;
            Ok(s.to_string().abi_encode())
        }
        _ => Err(MerkleTreeError::AbiEncode(format!(
            "Unsupported type: {}",
            sol_type
        ))),
    }
}

fn parse_uint256(value: &serde_json::Value) -> Result<alloy_primitives::U256> {
    match value {
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(alloy_primitives::U256::from(u))
            } else {
                Err(MerkleTreeError::AbiEncode(
                    "Number too large for u64, use string".into(),
                ))
            }
        }
        serde_json::Value::String(s) => {
            let s = s.trim();
            if let Some(hex_str) = s.strip_prefix("0x") {
                alloy_primitives::U256::from_str_radix(hex_str, 16)
                    .map_err(|e| MerkleTreeError::AbiEncode(format!("Invalid hex uint256: {e}")))
            } else {
                alloy_primitives::U256::from_str_radix(s, 10)
                    .map_err(|e| MerkleTreeError::AbiEncode(format!("Invalid uint256: {e}")))
            }
        }
        _ => Err(MerkleTreeError::AbiEncode(
            "Expected number or string for uint256".into(),
        )),
    }
}

fn parse_int256(value: &serde_json::Value) -> Result<alloy_primitives::I256> {
    match value {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(alloy_primitives::I256::try_from(i)
                    .map_err(|e| MerkleTreeError::AbiEncode(format!("Invalid int256: {}", e)))?)
            } else {
                Err(MerkleTreeError::AbiEncode(
                    "Number too large, use string".into(),
                ))
            }
        }
        serde_json::Value::String(s) => {
            let s = s.trim();
            s.parse::<alloy_primitives::I256>()
                .map_err(|e| MerkleTreeError::AbiEncode(format!("Invalid int256: {}", e)))
        }
        _ => Err(MerkleTreeError::AbiEncode(
            "Expected number or string for int256".into(),
        )),
    }
}

fn parse_uint_generic<T: std::str::FromStr + TryFrom<u64>>(value: &serde_json::Value) -> Result<T>
where
    <T as std::str::FromStr>::Err: std::fmt::Display,
    <T as TryFrom<u64>>::Error: std::fmt::Display,
{
    match value {
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                T::try_from(u).map_err(|e| {
                    MerkleTreeError::AbiEncode(format!("Number conversion error: {}", e))
                })
            } else {
                Err(MerkleTreeError::AbiEncode("Invalid number".into()))
            }
        }
        serde_json::Value::String(s) => s
            .parse::<T>()
            .map_err(|e| MerkleTreeError::AbiEncode(format!("Invalid number: {}", e))),
        _ => Err(MerkleTreeError::AbiEncode(
            "Expected number or string".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_standard_merkle_tree_basic() {
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

        let tree = StandardMerkleTree::of(
            values.clone(),
            vec!["address".to_string(), "uint256".to_string()],
            MerkleTreeOptions::default(),
        )
        .unwrap();

        assert_eq!(tree.len(), 2);
        assert!(!tree.root().is_empty());
    }

    #[test]
    fn test_proof_verification() {
        let values = vec![
            vec![
                json!("0x1111111111111111111111111111111111111111"),
                json!(100u64),
            ],
            vec![
                json!("0x2222222222222222222222222222222222222222"),
                json!(200u64),
            ],
            vec![
                json!("0x3333333333333333333333333333333333333333"),
                json!(300u64),
            ],
            vec![
                json!("0x4444444444444444444444444444444444444444"),
                json!(400u64),
            ],
        ];

        let tree = StandardMerkleTree::of(
            values.clone(),
            vec!["address".to_string(), "uint256".to_string()],
            MerkleTreeOptions::default(),
        )
        .unwrap();

        for (i, value) in values.iter().enumerate() {
            let proof = tree.get_proof(value).unwrap();
            assert!(tree.verify_proof(value, &proof).unwrap());
            assert!(tree.verify_proof_by_index(i, &proof).unwrap());
        }
    }

    #[test]
    fn test_dump_and_load() {
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

        let tree = StandardMerkleTree::of(
            values,
            vec!["address".to_string(), "uint256".to_string()],
            MerkleTreeOptions::default(),
        )
        .unwrap();

        let data = tree.dump();
        let json_str = serde_json::to_string(&data).unwrap();
        let loaded_data: StandardMerkleTreeData = serde_json::from_str(&json_str).unwrap();
        let loaded_tree = StandardMerkleTree::load(loaded_data).unwrap();

        assert_eq!(tree.root(), loaded_tree.root());
        assert_eq!(tree.len(), loaded_tree.len());
    }
}
