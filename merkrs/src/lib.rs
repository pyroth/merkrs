//! # merkrs
//!
//! A Rust implementation of Merkle tree library, compatible with OpenZeppelin's JavaScript implementation.
//!
//! ## Features
//!
//! - **`StandardMerkleTree`**: For structured data with ABI encoding (Solidity compatible)
//! - **`SimpleMerkleTree`**: For simple bytes32 values
//! - Full proof generation and verification
//! - Multi-proof support
//! - Serialization/deserialization with serde
//! - Keccak256 hashing (Ethereum compatible)
//!
//! ## Example
//!
//! ```rust
//! use merkrs::{SimpleMerkleTree, SimpleMerkleTreeOptions, Bytes32};
//!
//! let values: Vec<Bytes32> = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
//! let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();
//!
//! let proof = tree.get_proof(&values[0]).unwrap();
//! assert!(tree.verify_proof(&values[0], &proof).unwrap());
//! ```

#![deny(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

pub mod bytes;
pub mod core;
pub mod error;
pub mod hashes;
pub mod options;
pub mod simple;
pub mod standard;

pub use bytes::{Bytes32, HexString, ToBytes32};
pub use core::MultiProof;
pub use error::{MerkleTreeError, Result};
pub use hashes::{NodeHashFn, keccak256, standard_leaf_hash, standard_node_hash};
pub use options::MerkleTreeOptions;
pub use simple::{SimpleMerkleTree, SimpleMerkleTreeData, SimpleMerkleTreeOptions};
pub use standard::{StandardMerkleTree, StandardMerkleTreeData};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_simple_tree_e2e() {
        let values: Vec<Bytes32> = (0..4)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = i;
                bytes
            })
            .collect();

        let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

        assert_eq!(tree.len(), 4);

        for value in &values {
            let proof = tree.get_proof(value).unwrap();
            assert!(tree.verify_proof(value, &proof).unwrap());
        }

        let data = tree.dump();
        let loaded = SimpleMerkleTree::load(data, None).unwrap();
        assert_eq!(tree.root(), loaded.root());
    }

    #[test]
    fn test_standard_tree_e2e() {
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

        assert_eq!(tree.len(), 4);

        for value in &values {
            let proof = tree.get_proof(value).unwrap();
            assert!(tree.verify_proof(value, &proof).unwrap());
        }

        let data = tree.dump();
        let json_str = serde_json::to_string_pretty(&data).unwrap();
        let loaded_data: StandardMerkleTreeData = serde_json::from_str(&json_str).unwrap();
        let loaded = StandardMerkleTree::load(loaded_data).unwrap();
        assert_eq!(tree.root(), loaded.root());
    }

    #[test]
    fn test_static_verification() {
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

        let proof = tree.get_proof(&values[0]).unwrap();

        let result = StandardMerkleTree::verify(
            tree.root(),
            &["address".to_string(), "uint256".to_string()],
            &values[0],
            &proof,
        )
        .unwrap();

        assert!(result);
    }
}
