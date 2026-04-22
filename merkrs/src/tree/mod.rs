//! Flat-array Merkle tree primitives shared by `simple` and `standard` trees.
//!
//! All operations in this module work on a raw `&[Bytes32]` slice and a
//! caller-supplied [`NodeHashFn`](crate::hashes::NodeHashFn). Higher-level
//! wrappers live in [`crate::merkle`].

mod builder;
mod index;
mod multi_proof;
mod proof;
mod render;

pub(crate) use builder::{build, is_valid};
pub use multi_proof::{MultiProof, MultiProofJson};
pub(crate) use multi_proof::{multi_proof, process_multi_proof};
pub(crate) use proof::{process_proof, proof};
pub(crate) use render::render;
