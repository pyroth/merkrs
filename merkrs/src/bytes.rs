use crate::error::{MerkleTreeError, Result};
use alloy_primitives::B256;
use std::cmp::Ordering;

pub type Bytes32 = [u8; 32];
pub type HexString = String;

pub trait ToBytes32 {
    fn to_bytes32(&self) -> Result<Bytes32>;
}

impl ToBytes32 for [u8; 32] {
    fn to_bytes32(&self) -> Result<Bytes32> {
        Ok(*self)
    }
}

impl ToBytes32 for &[u8] {
    fn to_bytes32(&self) -> Result<Bytes32> {
        if self.len() != 32 {
            return Err(MerkleTreeError::InvalidNodeLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(self);
        Ok(arr)
    }
}

impl ToBytes32 for Vec<u8> {
    fn to_bytes32(&self) -> Result<Bytes32> {
        self.as_slice().to_bytes32()
    }
}

impl ToBytes32 for &str {
    fn to_bytes32(&self) -> Result<Bytes32> {
        hex_to_bytes32(self)
    }
}

impl ToBytes32 for String {
    fn to_bytes32(&self) -> Result<Bytes32> {
        hex_to_bytes32(self)
    }
}

impl ToBytes32 for &String {
    fn to_bytes32(&self) -> Result<Bytes32> {
        hex_to_bytes32(self)
    }
}

impl ToBytes32 for B256 {
    fn to_bytes32(&self) -> Result<Bytes32> {
        Ok(self.0)
    }
}

pub fn hex_to_bytes32(s: &str) -> Result<Bytes32> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| MerkleTreeError::HexDecode(e.to_string()))?;
    bytes.as_slice().to_bytes32()
}

#[must_use]
pub fn bytes32_to_hex(bytes: &Bytes32) -> HexString {
    format!("0x{}", hex::encode(bytes))
}

pub fn to_hex<T: ToBytes32>(value: &T) -> Result<HexString> {
    Ok(bytes32_to_hex(&value.to_bytes32()?))
}

#[must_use]
pub fn compare_bytes32(a: &Bytes32, b: &Bytes32) -> Ordering {
    for i in 0..32 {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

#[must_use]
pub fn concat_sorted(a: &Bytes32, b: &Bytes32) -> Vec<u8> {
    let mut result = Vec::with_capacity(64);
    if compare_bytes32(a, b) == Ordering::Less {
        result.extend_from_slice(a);
        result.extend_from_slice(b);
    } else {
        result.extend_from_slice(b);
        result.extend_from_slice(a);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MerkleTreeError;

    #[test]
    fn test_hex_roundtrip() {
        let original = [0xab; 32];
        let hex = bytes32_to_hex(&original);
        assert!(hex.starts_with("0x"));
        let recovered = hex_to_bytes32(&hex).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_hex_without_prefix() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let bytes = hex_to_bytes32(hex).unwrap();
        assert_eq!(bytes[31], 1);
    }

    #[test]
    fn test_hex_with_prefix() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let bytes = hex_to_bytes32(hex).unwrap();
        assert_eq!(bytes[31], 1);
    }

    #[test]
    fn test_invalid_hex_length() {
        let result = hex_to_bytes32("0x00");
        assert!(matches!(result, Err(MerkleTreeError::InvalidNodeLength)));
    }

    #[test]
    fn test_compare_bytes32() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1;

        assert_eq!(compare_bytes32(&a, &b), Ordering::Less);
        assert_eq!(compare_bytes32(&b, &a), Ordering::Greater);
        assert_eq!(compare_bytes32(&a, &a), Ordering::Equal);
    }

    #[test]
    fn test_compare_bytes32_first_byte() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 1;
        b[0] = 2;

        assert_eq!(compare_bytes32(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_to_bytes32_from_slice() {
        let slice: &[u8] = &[1u8; 32];
        let bytes = slice.to_bytes32().unwrap();
        assert_eq!(bytes, [1u8; 32]);
    }

    #[test]
    fn test_to_bytes32_from_vec() {
        let vec = vec![2u8; 32];
        let bytes = vec.to_bytes32().unwrap();
        assert_eq!(bytes, [2u8; 32]);
    }

    #[test]
    fn test_to_bytes32_wrong_length() {
        let slice: &[u8] = &[1u8; 31];
        let result = slice.to_bytes32();
        assert!(matches!(result, Err(MerkleTreeError::InvalidNodeLength)));
    }
}
