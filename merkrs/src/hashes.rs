use sha3::{Digest, Keccak256};

use crate::bytes::{Bytes32, concat_sorted};

/// Compute the Keccak-256 hash of arbitrary data.
#[must_use]
pub fn keccak256(data: &[u8]) -> Bytes32 {
    let hash = Keccak256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::bytes_to_hex;

    #[test]
    fn keccak256_known_value() {
        let hash = keccak256(b"hello");
        assert_eq!(
            bytes_to_hex(&hash),
            "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn keccak256_empty() {
        let hash = keccak256(b"");
        assert_eq!(
            bytes_to_hex(&hash),
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
}
