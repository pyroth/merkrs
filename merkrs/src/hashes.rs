//! Keccak-256 hashing primitives.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::bytes::Bytes32;

/// Marker for which node-hash strategy a serialised tree was built with.
///
/// `None` implies the default [`standard_node_hash`]. `Some(NodeHashKind::Custom)`
/// records that a caller-supplied hash was used, so the same hash must be
/// passed when reconstructing the tree from JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeHashKind {
    /// A user-provided node hash other than [`standard_node_hash`].
    Custom,
}

/// Compute the Keccak-256 hash of arbitrary data.
#[must_use]
pub fn keccak256(data: &[u8]) -> Bytes32 {
    Keccak256::digest(data).into()
}

/// Double-hash used for standard Merkle tree leaves (prevents second-preimage attacks).
#[must_use]
pub fn standard_leaf_hash(data: &[u8]) -> Bytes32 {
    keccak256(&keccak256(data))
}

/// Signature for a function that hashes two sibling nodes into their parent.
pub type NodeHashFn = fn(&Bytes32, &Bytes32) -> Bytes32;

/// Default node hash: `keccak256(sort(a, b))`.
#[must_use]
pub fn standard_node_hash(a: &Bytes32, b: &Bytes32) -> Bytes32 {
    keccak256(&concat_sorted(a, b))
}

fn concat_sorted(a: &Bytes32, b: &Bytes32) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    buf[..32].copy_from_slice(lo);
    buf[32..].copy_from_slice(hi);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::encode_hex;

    #[test]
    fn keccak256_known_value() {
        let hash = keccak256(b"hello");
        assert_eq!(
            encode_hex(&hash),
            "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn keccak256_empty() {
        let hash = keccak256(b"");
        assert_eq!(
            encode_hex(&hash),
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn node_hash_is_commutative() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(standard_node_hash(&a, &b), standard_node_hash(&b, &a));
    }

    #[test]
    fn leaf_hash_is_double_keccak() {
        let input = [0u8; 32];
        assert_eq!(standard_leaf_hash(&input), keccak256(&keccak256(&input)));
    }

    #[test]
    fn concat_sorted_is_commutative() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1;
        assert_eq!(concat_sorted(&a, &b), concat_sorted(&b, &a));
        assert_eq!(&concat_sorted(&a, &b)[..32], &a);
        assert_eq!(&concat_sorted(&a, &b)[32..], &b);
    }
}
