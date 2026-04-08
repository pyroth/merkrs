use crate::error::{Error, Result};

/// A 32-byte hash value used as tree nodes and leaves.
pub type Bytes32 = [u8; 32];

/// Parse a hex string (with optional `0x` prefix) into [`Bytes32`].
pub fn hex_to_bytes(s: &str) -> Result<Bytes32> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| Error::HexDecode(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(Error::InvalidNodeLength(bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Encode [`Bytes32`] as a `0x`-prefixed hex string.
#[must_use]
pub fn bytes_to_hex(bytes: &Bytes32) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Concatenate two hashes in sorted (ascending) order into a 64-byte buffer.
#[must_use]
pub fn concat_sorted(a: &Bytes32, b: &Bytes32) -> [u8; 64] {
    let mut buf = [0u8; 64];
    if a <= b {
        buf[..32].copy_from_slice(a);
        buf[32..].copy_from_slice(b);
    } else {
        buf[..32].copy_from_slice(b);
        buf[32..].copy_from_slice(a);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let original = [0xab; 32];
        let hex = bytes_to_hex(&original);
        assert!(hex.starts_with("0x"), "should have 0x prefix");
        let recovered = hex_to_bytes(&hex).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn hex_without_prefix() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let bytes = hex_to_bytes(hex).unwrap();
        assert_eq!(bytes[31], 1);
    }

    #[test]
    fn hex_with_prefix() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let bytes = hex_to_bytes(hex).unwrap();
        assert_eq!(bytes[31], 1);
    }

    #[test]
    fn invalid_hex_length() {
        let result = hex_to_bytes("0x00");
        assert!(matches!(result, Err(Error::InvalidNodeLength(1))));
    }

    #[test]
    fn concat_sorted_order() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1;
        let fwd = concat_sorted(&a, &b);
        let rev = concat_sorted(&b, &a);
        assert_eq!(fwd, rev, "concat_sorted must be commutative");
        assert_eq!(&fwd[..32], &a);
        assert_eq!(&fwd[32..], &b);
    }
}
