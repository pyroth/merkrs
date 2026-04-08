//! # merkrs
//!
//! A Rust Merkle tree library compatible with
//! [OpenZeppelin's JavaScript implementation](https://docs.openzeppelin.com/contracts/4.x/api/utils#MerkleProof).
//!
//! ## Features
//!
//! - **[`StandardMerkleTree`]** — ABI-encoded Solidity values with double leaf hashing
//! - **[`SimpleMerkleTree`]** — raw `[u8; 32]` values with single leaf hashing
//! - Single-leaf and multi-proof generation / verification
//! - Serialisation compatible with the OZ JavaScript `standard-v1` / `simple-v1` formats
//! - Keccak-256 hashing (Ethereum compatible)
//!
//! ## Quick start
//!
//! ```rust
//! use merkrs::{SimpleMerkleTree, simple::Options, Bytes32};
//!
//! let values: Vec<Bytes32> = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
//! let tree = SimpleMerkleTree::new(&values, Options::default()).unwrap();
//!
//! let proof = tree.proof(&values[0]).unwrap();
//! assert!(tree.verify_proof(&values[0], &proof).unwrap());
//! ```

mod abi;
pub mod bytes;
pub mod error;
pub mod hashes;
pub mod merkle;
pub mod simple;
pub mod standard;
mod tree;

pub use bytes::Bytes32;
pub use error::{Error, Result};
pub use hashes::{NodeHashFn, keccak256, standard_leaf_hash, standard_node_hash};
pub use merkle::{LeafHasher, MerkleTree};
#[cfg(test)]
use pretty_assertions as _;
pub use simple::SimpleMerkleTree;
pub use simple::SimpleMerkleTreeData;
pub use standard::{StandardMerkleTree, StandardMerkleTreeData};
pub use tree::{MultiProof, MultiProofJson};
