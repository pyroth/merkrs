use crate::bytes::{Bytes32, ToBytes32, concat_sorted};
use crate::error::Result;
use sha3::{Digest, Keccak256};

#[must_use]
pub fn keccak256(data: &[u8]) -> Bytes32 {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

#[must_use]
pub fn standard_leaf_hash(data: &[u8]) -> Bytes32 {
    keccak256(&keccak256(data))
}

pub fn standard_node_hash<A: ToBytes32, B: ToBytes32>(a: &A, b: &B) -> Result<Bytes32> {
    let a_bytes = a.to_bytes32()?;
    let b_bytes = b.to_bytes32()?;
    let concatenated = concat_sorted(&a_bytes, &b_bytes);
    Ok(keccak256(&concatenated))
}

pub type NodeHashFn = fn(&Bytes32, &Bytes32) -> Bytes32;

#[must_use]
pub fn default_node_hash(a: &Bytes32, b: &Bytes32) -> Bytes32 {
    let concatenated = concat_sorted(a, b);
    keccak256(&concatenated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::bytes32_to_hex;

    #[test]
    fn test_keccak256_known_value() {
        let input = b"hello";
        let hash = keccak256(input);
        let hex = bytes32_to_hex(&hash);
        assert_eq!(
            hex,
            "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_keccak256_empty() {
        let input = b"";
        let hash = keccak256(input);
        let hex = bytes32_to_hex(&hash);
        assert_eq!(
            hex,
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn test_standard_node_hash_commutative() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        let hash1 = standard_node_hash(&a, &b).unwrap();
        let hash2 = standard_node_hash(&b, &a).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_default_node_hash_commutative() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        let hash1 = default_node_hash(&a, &b);
        let hash2 = default_node_hash(&b, &a);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_standard_leaf_hash_double_hash() {
        let input = [0u8; 32];
        let leaf_hash = standard_leaf_hash(&input);
        let expected = keccak256(&keccak256(&input));
        assert_eq!(leaf_hash, expected);
    }
}
