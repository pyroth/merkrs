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
//! use merkrs::{Bytes32, SimpleMerkleTree, simple};
//!
//! # fn main() -> merkrs::Result<()> {
//! let values: Vec<Bytes32> = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
//! let tree = SimpleMerkleTree::new(&values, simple::Options::default())?;
//!
//! let proof = tree.proof(&values[0])?;
//! assert!(tree.verify_proof(&values[0], &proof)?);
//! # Ok(())
//! # }
//! ```

mod abi;
pub mod bytes;
pub mod error;
pub mod hashes;
pub mod merkle;
pub mod simple;
pub mod standard;
pub mod tree;

pub use bytes::Bytes32;
pub use error::{Error, Result};
pub use hashes::{NodeHashFn, NodeHashKind, keccak256, standard_leaf_hash, standard_node_hash};
pub use merkle::{LeafHasher, MerkleTree};
#[cfg(test)]
use pretty_assertions as _;
pub use simple::{SimpleMerkleTree, SimpleMerkleTreeData};
pub use standard::{StandardMerkleTree, StandardMerkleTreeData};
pub use tree::{MultiProof, MultiProofJson};
