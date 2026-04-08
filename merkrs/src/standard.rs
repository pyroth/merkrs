use ahash::AHashMap;
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

use crate::bytes::{Bytes32, bytes_to_hex, hex_to_bytes};
use crate::error::{Error, Result};
use crate::hashes::{standard_leaf_hash, standard_node_hash};
use crate::tree::{self, MultiProof};

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

/// A Merkle tree over ABI-encoded Solidity values.
///
/// Leaves are double-hashed (`keccak256(keccak256(abi.encode(...)))`) to
/// prevent second-preimage attacks, matching the OpenZeppelin convention.
#[derive(Debug)]
pub struct StandardMerkleTree {
    tree: Vec<Bytes32>,
    values: Vec<Vec<serde_json::Value>>,
    tree_indices: Vec<usize>,
    leaf_encoding: Vec<String>,
    hash_lookup: AHashMap<Bytes32, usize>,
}

impl StandardMerkleTree {
    /// Build a tree from ABI-typed values.
    pub fn of(
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
            indexed.sort_unstable_by(|a, b| a.1.cmp(&b.1));
        }

        let leaves: Vec<Bytes32> = indexed.iter().map(|(_, h)| *h).collect();
        let tree = tree::build(&leaves, standard_node_hash)?;

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
            values,
            tree_indices,
            leaf_encoding,
            hash_lookup,
        })
    }

    /// Reconstruct from a serialised snapshot.
    pub fn load(data: StandardMerkleTreeData) -> Result<Self> {
        if data.format != "standard-v1" {
            return Err(Error::UnknownFormat(data.format));
        }
        if data.leaf_encoding.is_empty() {
            return Err(Error::MissingLeafEncoding);
        }

        let tree: Vec<Bytes32> = data
            .tree
            .iter()
            .map(|s| hex_to_bytes(s))
            .collect::<Result<_>>()?;

        let mut values = Vec::with_capacity(data.values.len());
        let mut tree_indices = Vec::with_capacity(data.values.len());
        for entry in data.values {
            tree_indices.push(entry.tree_index);
            values.push(entry.value);
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
            leaf_encoding: data.leaf_encoding,
            hash_lookup,
        };
        me.validate()?;
        Ok(me)
    }

    /// Verify a single leaf against a known root without a tree instance.
    pub fn verify(
        root: &Bytes32,
        leaf_encoding: &[String],
        leaf: &[serde_json::Value],
        proof: &[Bytes32],
    ) -> Result<bool> {
        let hash = compute_leaf_hash(leaf_encoding, leaf)?;
        Ok(tree::process_proof(&hash, proof, standard_node_hash) == *root)
    }

    /// The Merkle root hash.
    #[must_use]
    pub fn root(&self) -> &Bytes32 {
        &self.tree[0]
    }

    /// Number of leaves.
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
    pub fn get(&self, index: usize) -> Option<&Vec<serde_json::Value>> {
        self.values.get(index)
    }

    /// Iterate over `(index, value)` pairs.
    pub fn entries(&self) -> impl Iterator<Item = (usize, &Vec<serde_json::Value>)> {
        self.values.iter().enumerate()
    }

    /// Serialise to a JSON-friendly snapshot.
    #[must_use]
    pub fn dump(&self) -> StandardMerkleTreeData {
        let tree_hex: Vec<String> = self.tree.iter().map(bytes_to_hex).collect();
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
            format: "standard-v1".into(),
            leaf_encoding: self.leaf_encoding.clone(),
            tree: tree_hex,
            values,
        }
    }

    /// Pretty-print the tree structure.
    pub fn render(&self) -> Result<String> {
        tree::render(&self.tree)
    }

    /// Validate internal consistency.
    pub fn validate(&self) -> Result<()> {
        for (i, (val, &ti)) in self.values.iter().zip(&self.tree_indices).enumerate() {
            let expected = compute_leaf_hash(&self.leaf_encoding, val)?;
            if self.tree[ti] != expected {
                return Err(Error::ValueMismatch(i));
            }
        }
        if !tree::is_valid(&self.tree, standard_node_hash) {
            return Err(Error::InvalidTree);
        }
        Ok(())
    }

    /// Look up the value-index for a given leaf.
    pub fn leaf_lookup(&self, leaf: &[serde_json::Value]) -> Result<usize> {
        let hash = compute_leaf_hash(&self.leaf_encoding, leaf)?;
        self.hash_lookup
            .get(&hash)
            .copied()
            .ok_or(Error::LeafNotFound)
    }

    /// Generate a proof for the value at `index`.
    pub fn get_proof_by_index(&self, index: usize) -> Result<Vec<Bytes32>> {
        let len = self.values.len();
        if index >= len {
            return Err(Error::IndexOutOfBounds { index, len });
        }
        let ti = self.tree_indices[index];
        let p = tree::proof(&self.tree, ti)?;
        let root = tree::process_proof(&self.tree[ti], &p, standard_node_hash);
        if root != self.tree[0] {
            return Err(Error::UnableToProve(index));
        }
        Ok(p)
    }

    /// Generate a proof for a given leaf value.
    pub fn get_proof(&self, leaf: &[serde_json::Value]) -> Result<Vec<Bytes32>> {
        self.get_proof_by_index(self.leaf_lookup(leaf)?)
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
        let root = tree::process_multi_proof(&mp, standard_node_hash)?;
        if root != self.tree[0] {
            return Err(Error::UnableToProve(0));
        }
        Ok(mp)
    }

    /// Verify a proof for a given leaf.
    pub fn verify_proof(&self, leaf: &[serde_json::Value], proof: &[Bytes32]) -> Result<bool> {
        let hash = compute_leaf_hash(&self.leaf_encoding, leaf)?;
        Ok(tree::process_proof(&hash, proof, standard_node_hash) == self.tree[0])
    }

    /// Verify a proof for the value at `index`.
    pub fn verify_proof_by_index(&self, index: usize, proof: &[Bytes32]) -> Result<bool> {
        let len = self.values.len();
        if index >= len {
            return Err(Error::IndexOutOfBounds { index, len });
        }
        let hash = compute_leaf_hash(&self.leaf_encoding, &self.values[index])?;
        Ok(tree::process_proof(&hash, proof, standard_node_hash) == self.tree[0])
    }
}

fn compute_leaf_hash(types: &[String], values: &[serde_json::Value]) -> Result<Bytes32> {
    let encoded = encode_leaf(types, values)?;
    Ok(standard_leaf_hash(&encoded))
}

fn encode_leaf(types: &[String], values: &[serde_json::Value]) -> Result<Vec<u8>> {
    if types.len() != values.len() {
        return Err(Error::AbiEncode("types and values length mismatch".into()));
    }
    let mut encoded = Vec::new();
    for (sol_type, value) in types.iter().zip(values.iter()) {
        encoded.extend(encode_single_value(sol_type, value)?);
    }
    Ok(encoded)
}

fn encode_single_value(sol_type: &str, value: &serde_json::Value) -> Result<Vec<u8>> {
    match sol_type {
        "address" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::AbiEncode("expected string for address".into()))?;
            let addr: alloy_primitives::Address = s
                .parse()
                .map_err(|e| Error::AbiEncode(format!("invalid address: {e}")))?;
            Ok(addr.abi_encode())
        }
        "uint256" => Ok(parse_uint256(value)?.abi_encode()),
        "uint128" => {
            let n: u128 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(n).abi_encode())
        }
        "uint64" => {
            let n: u64 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(n).abi_encode())
        }
        "uint32" => {
            let n: u32 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(n).abi_encode())
        }
        "uint16" => {
            let n: u16 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(n).abi_encode())
        }
        "uint8" => {
            let n: u8 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(n).abi_encode())
        }
        "int256" => Ok(parse_int256(value)?.abi_encode()),
        "bytes32" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::AbiEncode("expected string for bytes32".into()))?;
            let b32: alloy_primitives::B256 = s
                .parse()
                .map_err(|e| Error::AbiEncode(format!("invalid bytes32: {e}")))?;
            Ok(b32.abi_encode())
        }
        "bytes" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::AbiEncode("expected string for bytes".into()))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes =
                hex::decode(s).map_err(|e| Error::AbiEncode(format!("invalid hex: {e}")))?;
            Ok(alloy_primitives::Bytes::from(bytes).abi_encode())
        }
        "bool" => {
            let b = value
                .as_bool()
                .ok_or_else(|| Error::AbiEncode("expected bool".into()))?;
            Ok(if b {
                alloy_primitives::U256::from(1)
            } else {
                alloy_primitives::U256::ZERO
            }
            .abi_encode())
        }
        "string" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::AbiEncode("expected string".into()))?;
            Ok(s.to_owned().abi_encode())
        }
        _ => Err(Error::AbiEncode(format!("unsupported type: {sol_type}"))),
    }
}

fn parse_uint256(value: &serde_json::Value) -> Result<alloy_primitives::U256> {
    match value {
        serde_json::Value::Number(n) => n
            .as_u64()
            .map(alloy_primitives::U256::from)
            .ok_or_else(|| Error::AbiEncode("number too large for u64, use string".into())),
        serde_json::Value::String(s) => {
            let s = s.trim();
            if let Some(hex_str) = s.strip_prefix("0x") {
                alloy_primitives::U256::from_str_radix(hex_str, 16)
                    .map_err(|e| Error::AbiEncode(format!("invalid hex uint256: {e}")))
            } else {
                alloy_primitives::U256::from_str_radix(s, 10)
                    .map_err(|e| Error::AbiEncode(format!("invalid uint256: {e}")))
            }
        }
        _ => Err(Error::AbiEncode(
            "expected number or string for uint256".into(),
        )),
    }
}

fn parse_int256(value: &serde_json::Value) -> Result<alloy_primitives::I256> {
    match value {
        serde_json::Value::Number(n) => n
            .as_i64()
            .ok_or_else(|| Error::AbiEncode("number too large, use string".into()))
            .and_then(|i| {
                alloy_primitives::I256::try_from(i)
                    .map_err(|e| Error::AbiEncode(format!("invalid int256: {e}")))
            }),
        serde_json::Value::String(s) => s
            .trim()
            .parse::<alloy_primitives::I256>()
            .map_err(|e| Error::AbiEncode(format!("invalid int256: {e}"))),
        _ => Err(Error::AbiEncode(
            "expected number or string for int256".into(),
        )),
    }
}

fn parse_uint_generic<T: std::str::FromStr + TryFrom<u64>>(value: &serde_json::Value) -> Result<T>
where
    <T as std::str::FromStr>::Err: std::fmt::Display,
    <T as TryFrom<u64>>::Error: std::fmt::Display,
{
    match value {
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| Error::AbiEncode("invalid number".into()))
            .and_then(|u| {
                T::try_from(u)
                    .map_err(|e| Error::AbiEncode(format!("number conversion error: {e}")))
            }),
        serde_json::Value::String(s) => s
            .parse::<T>()
            .map_err(|e| Error::AbiEncode(format!("invalid number: {e}"))),
        _ => Err(Error::AbiEncode("expected number or string".into())),
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
            StandardMerkleTree::of(airdrop_data(4), encoding(), Options::default()).unwrap();
        assert_eq!(tree.leaf_count(), 4);
        tree.validate().unwrap();
    }

    #[test]
    fn single_leaf() {
        let tree =
            StandardMerkleTree::of(airdrop_data(1), encoding(), Options::default()).unwrap();
        assert_eq!(tree.leaf_count(), 1);
        tree.validate().unwrap();
    }

    #[test]
    fn proof_roundtrip() {
        let values = airdrop_data(8);
        let tree =
            StandardMerkleTree::of(values.clone(), encoding(), Options::default()).unwrap();
        for (i, v) in values.iter().enumerate() {
            let p = tree.get_proof(v).unwrap();
            assert!(tree.verify_proof(v, &p).unwrap());
            assert!(tree.verify_proof_by_index(i, &p).unwrap());
        }
    }

    #[test]
    fn static_verify() {
        let values = airdrop_data(4);
        let enc = encoding();
        let tree = StandardMerkleTree::of(values.clone(), enc.clone(), Options::default()).unwrap();
        for v in &values {
            let p = tree.get_proof(v).unwrap();
            assert!(StandardMerkleTree::verify(tree.root(), &enc, v, &p).unwrap());
        }
    }

    #[test]
    fn reject_invalid_proof() {
        let v1 = airdrop_data(4);
        let t1 = StandardMerkleTree::of(v1.clone(), encoding(), Options::default()).unwrap();
        let v2: Vec<_> = airdrop_data(4)
            .into_iter()
            .map(|mut v| {
                v[1] = json!(9999);
                v
            })
            .collect();
        let t2 = StandardMerkleTree::of(v2, encoding(), Options::default()).unwrap();
        let proof = t1.get_proof(&v1[0]).unwrap();
        assert!(!t2.verify_proof(&v1[0], &proof).unwrap());
    }

    #[test]
    fn multiproof() {
        let tree =
            StandardMerkleTree::of(airdrop_data(8), encoding(), Options::default()).unwrap();
        let mp = tree.get_multi_proof_by_indices(&[0, 2, 5]).unwrap();
        assert_eq!(mp.leaves.len(), 3);
    }

    #[test]
    fn dump_and_load() {
        let tree =
            StandardMerkleTree::of(airdrop_data(4), encoding(), Options::default()).unwrap();
        let data = tree.dump();
        assert_eq!(data.format, "standard-v1");
        let json_str = serde_json::to_string(&data).unwrap();
        let loaded_data: StandardMerkleTreeData = serde_json::from_str(&json_str).unwrap();
        let loaded = StandardMerkleTree::load(loaded_data).unwrap();
        assert_eq!(tree.root(), loaded.root());
        assert_eq!(tree.leaf_count(), loaded.leaf_count());
    }

    #[test]
    fn entries_match_get() {
        let tree =
            StandardMerkleTree::of(airdrop_data(4), encoding(), Options::default()).unwrap();
        for (i, v) in tree.entries() {
            assert_eq!(Some(v), tree.get(i));
        }
        assert!(tree.get(tree.leaf_count()).is_none());
    }

    #[test]
    fn unsorted_leaves() {
        let values = airdrop_data(4);
        let tree = StandardMerkleTree::of(
            values.clone(),
            encoding(),
            Options::default().with_sort_leaves(false),
        )
        .unwrap();
        tree.validate().unwrap();
        for v in &values {
            let p = tree.get_proof(v).unwrap();
            assert!(tree.verify_proof(v, &p).unwrap());
        }
    }

    #[test]
    fn various_types() {
        let values = vec![
            vec![json!("0x1111111111111111111111111111111111111111"), json!(100u64)],
            vec![json!("0x2222222222222222222222222222222222222222"), json!(200u64)],
        ];
        let tree =
            StandardMerkleTree::of(values.clone(), encoding(), Options::default()).unwrap();
        for v in &values {
            let p = tree.get_proof(v).unwrap();
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
        let tree = StandardMerkleTree::of(
            values.clone(),
            vec!["bytes32".into(), "uint256".into()],
            Options::default(),
        )
        .unwrap();
        for v in &values {
            let p = tree.get_proof(v).unwrap();
            assert!(tree.verify_proof(v, &p).unwrap());
        }
    }

    #[test]
    fn uint_types() {
        let values = vec![
            vec![json!(100u64), json!(200u64), json!(50u64)],
            vec![json!(300u64), json!(400u64), json!(60u64)],
        ];
        let tree = StandardMerkleTree::of(
            values.clone(),
            vec!["uint256".into(), "uint128".into(), "uint64".into()],
            Options::default(),
        )
        .unwrap();
        for v in &values {
            let p = tree.get_proof(v).unwrap();
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
            StandardMerkleTree::load(data),
            Err(Error::UnknownFormat(_))
        ));
    }

    #[test]
    fn out_of_bounds() {
        let tree =
            StandardMerkleTree::of(airdrop_data(4), encoding(), Options::default()).unwrap();
        assert!(matches!(
            tree.get_proof_by_index(100),
            Err(Error::IndexOutOfBounds { .. })
        ));
    }

    #[test]
    fn leaf_not_found() {
        let tree =
            StandardMerkleTree::of(airdrop_data(4), encoding(), Options::default()).unwrap();
        let bad = vec![json!("0x9999999999999999999999999999999999999999"), json!(9999)];
        assert!(matches!(tree.get_proof(&bad), Err(Error::LeafNotFound)));
    }

    #[test]
    fn large_tree() {
        let values = airdrop_data(100);
        let tree =
            StandardMerkleTree::of(values.clone(), encoding(), Options::default()).unwrap();
        assert_eq!(tree.leaf_count(), 100);
        tree.validate().unwrap();
        for i in [0, 25, 50, 75, 99] {
            let p = tree.get_proof(&values[i]).unwrap();
            assert!(tree.verify_proof(&values[i], &p).unwrap());
        }
    }
}
