//! Solidity ABI encoding for [`StandardMerkleTree`](crate::StandardMerkleTree) leaves.
//!
//! JSON values are coerced into [`alloy_dyn_abi::DynSolValue`]s, assembled as a
//! tuple, and encoded with the standard non-packed ABI layout to match
//! `abi.encode(...)` in Solidity.

use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_primitives::{Address, B256, I256, U256};
use serde_json::Value;

use crate::bytes::Bytes32;
use crate::error::{Error, Result};
use crate::hashes::standard_leaf_hash;

/// Compute the double-hashed leaf (`keccak256(keccak256(abi.encode(values)))`).
pub(crate) fn compute_leaf_hash(types: &[String], values: &[Value]) -> Result<Bytes32> {
    if types.len() != values.len() {
        return Err(Error::AbiEncode(format!(
            "type/value length mismatch: {} types vs {} values",
            types.len(),
            values.len()
        )));
    }

    let coerced = types
        .iter()
        .zip(values)
        .map(|(ty, val)| {
            let parsed = DynSolType::parse(ty)
                .map_err(|e| Error::AbiEncode(format!("invalid type '{ty}': {e}")))?;
            json_to_dyn_value(&parsed, val)
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(standard_leaf_hash(
        &DynSolValue::Tuple(coerced).abi_encode(),
    ))
}

fn json_to_dyn_value(ty: &DynSolType, value: &Value) -> Result<DynSolValue> {
    match ty {
        DynSolType::Address => {
            let addr: Address = expect_str(value, "address")?
                .parse()
                .map_err(|e| Error::AbiEncode(format!("invalid address: {e}")))?;
            Ok(DynSolValue::Address(addr))
        }
        DynSolType::Bool => {
            let b = match value {
                Value::Bool(b) => *b,
                Value::String(s) => s
                    .parse()
                    .map_err(|e| Error::AbiEncode(format!("invalid bool: {e}")))?,
                _ => return Err(Error::AbiEncode("expected bool".into())),
            };
            Ok(DynSolValue::Bool(b))
        }
        DynSolType::Uint(bits) => Ok(DynSolValue::Uint(parse_u256(value)?, *bits)),
        DynSolType::Int(bits) => Ok(DynSolValue::Int(parse_i256(value)?, *bits)),
        DynSolType::FixedBytes(n) => {
            let b32: B256 = expect_str(value, "fixed bytes")?
                .parse()
                .map_err(|e| Error::AbiEncode(format!("invalid bytes{n}: {e}")))?;
            Ok(DynSolValue::FixedBytes(b32, *n))
        }
        DynSolType::Bytes => {
            let s = expect_str(value, "bytes")?;
            let stripped = s.strip_prefix("0x").unwrap_or(s);
            let bytes =
                hex::decode(stripped).map_err(|e| Error::AbiEncode(format!("invalid hex: {e}")))?;
            Ok(DynSolValue::Bytes(bytes))
        }
        DynSolType::String => Ok(DynSolValue::String(expect_str(value, "string")?.to_owned())),
        other => Err(Error::AbiEncode(format!("unsupported type: {other}"))),
    }
}

fn expect_str<'v>(value: &'v Value, kind: &str) -> Result<&'v str> {
    value
        .as_str()
        .ok_or_else(|| Error::AbiEncode(format!("expected string for {kind}")))
}

fn parse_u256(value: &Value) -> Result<U256> {
    match value {
        Value::Number(n) => n
            .as_u128()
            .map(U256::from)
            .ok_or_else(|| Error::AbiEncode("number too large for u128; use string".into())),
        Value::String(s) => {
            let trimmed = s.trim();
            trimmed.strip_prefix("0x").map_or_else(
                || {
                    U256::from_str_radix(trimmed, 10)
                        .map_err(|e| Error::AbiEncode(format!("invalid uint: {e}")))
                },
                |hex| {
                    U256::from_str_radix(hex, 16)
                        .map_err(|e| Error::AbiEncode(format!("invalid hex uint: {e}")))
                },
            )
        }
        _ => Err(Error::AbiEncode(
            "expected number or string for uint".into(),
        )),
    }
}

fn parse_i256(value: &Value) -> Result<I256> {
    match value {
        Value::Number(n) => n
            .as_i128()
            .ok_or_else(|| Error::AbiEncode("number too large for i128; use string".into()))
            .and_then(|i| {
                I256::try_from(i).map_err(|e| Error::AbiEncode(format!("invalid int: {e}")))
            }),
        Value::String(s) => s
            .trim()
            .parse::<I256>()
            .map_err(|e| Error::AbiEncode(format!("invalid int: {e}"))),
        _ => Err(Error::AbiEncode("expected number or string for int".into())),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn length_mismatch_rejected() {
        let err = compute_leaf_hash(&["uint256".into()], &[]).unwrap_err();
        assert!(matches!(err, Error::AbiEncode(_)));
    }

    #[test]
    fn unsupported_type_rejected() {
        let err = compute_leaf_hash(&["not_a_type".into()], &[json!(0)]).unwrap_err();
        assert!(matches!(err, Error::AbiEncode(_)));
    }

    #[test]
    fn encodes_address_uint256_pair() {
        let a = compute_leaf_hash(
            &["address".into(), "uint256".into()],
            &[
                json!("0x1111111111111111111111111111111111111111"),
                json!(100),
            ],
        )
        .unwrap();
        let b = compute_leaf_hash(
            &["address".into(), "uint256".into()],
            &[
                json!("0x1111111111111111111111111111111111111111"),
                json!("100"),
            ],
        )
        .unwrap();
        assert_eq!(a, b, "numeric and stringified uint must hash identically");
    }

    #[test]
    fn encodes_dynamic_bytes_and_string() {
        let a = compute_leaf_hash(
            &["bytes".into(), "string".into()],
            &[json!("0xdeadbeef"), json!("hello")],
        )
        .unwrap();
        let b = compute_leaf_hash(
            &["bytes".into(), "string".into()],
            &[json!("0xDEADBEEF"), json!("hello")],
        )
        .unwrap();
        assert_eq!(a, b, "hex case must not affect the encoded bytes");
    }

    #[test]
    fn encodes_negative_int256() {
        let hash = compute_leaf_hash(&["int256".into()], &[json!("-1")]).unwrap();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn encodes_bool_and_fixed_bytes32() {
        let from_bool = compute_leaf_hash(&["bool".into()], &[json!(true)]).unwrap();
        let from_bool_str = compute_leaf_hash(&["bool".into()], &[json!("true")]).unwrap();
        assert_eq!(from_bool, from_bool_str);

        let fixed = compute_leaf_hash(
            &["bytes32".into()],
            &[json!(
                "0x1111111111111111111111111111111111111111111111111111111111111111"
            )],
        )
        .unwrap();
        assert_ne!(fixed, [0u8; 32]);
    }
}
