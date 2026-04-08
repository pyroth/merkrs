//! Solidity ABI encoding for [`StandardMerkleTree`](crate::StandardMerkleTree) leaves.

use alloy_sol_types::SolValue;

use crate::bytes::Bytes32;
use crate::error::{Error, Result};
use crate::hashes::standard_leaf_hash;

/// Compute the double-hashed leaf from ABI-typed values.
pub(crate) fn compute_leaf_hash(types: &[String], values: &[serde_json::Value]) -> Result<Bytes32> {
    let encoded = encode_leaf(types, values)?;
    Ok(standard_leaf_hash(&encoded))
}

fn encode_leaf(types: &[String], values: &[serde_json::Value]) -> Result<Vec<u8>> {
    if types.len() != values.len() {
        return Err(Error::AbiEncode("types and values length mismatch".into()));
    }
    let mut encoded = Vec::new();
    for (sol_type, value) in types.iter().zip(values.iter()) {
        encoded.extend(encode_single_value(sol_type, value)?);
    }
    Ok(encoded)
}

fn encode_single_value(sol_type: &str, value: &serde_json::Value) -> Result<Vec<u8>> {
    match sol_type {
        "address" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::AbiEncode("expected string for address".into()))?;
            let addr: alloy_primitives::Address = s
                .parse()
                .map_err(|e| Error::AbiEncode(format!("invalid address: {e}")))?;
            Ok(addr.abi_encode())
        }
        "uint256" => Ok(parse_uint256(value)?.abi_encode()),
        "uint128" => {
            let n: u128 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(n).abi_encode())
        }
        "uint64" => {
            let n: u64 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(n).abi_encode())
        }
        "uint32" => {
            let n: u32 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(n).abi_encode())
        }
        "uint16" => {
            let n: u16 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(n).abi_encode())
        }
        "uint8" => {
            let n: u8 = parse_uint_generic(value)?;
            Ok(alloy_primitives::U256::from(n).abi_encode())
        }
        "int256" => Ok(parse_int256(value)?.abi_encode()),
        "bytes32" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::AbiEncode("expected string for bytes32".into()))?;
            let b32: alloy_primitives::B256 = s
                .parse()
                .map_err(|e| Error::AbiEncode(format!("invalid bytes32: {e}")))?;
            Ok(b32.abi_encode())
        }
        "bytes" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::AbiEncode("expected string for bytes".into()))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes =
                hex::decode(s).map_err(|e| Error::AbiEncode(format!("invalid hex: {e}")))?;
            Ok(alloy_primitives::Bytes::from(bytes).abi_encode())
        }
        "bool" => {
            let b = value
                .as_bool()
                .ok_or_else(|| Error::AbiEncode("expected bool".into()))?;
            Ok(if b {
                alloy_primitives::U256::from(1)
            } else {
                alloy_primitives::U256::ZERO
            }
            .abi_encode())
        }
        "string" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::AbiEncode("expected string".into()))?;
            Ok(s.to_owned().abi_encode())
        }
        _ => Err(Error::AbiEncode(format!("unsupported type: {sol_type}"))),
    }
}

fn parse_uint256(value: &serde_json::Value) -> Result<alloy_primitives::U256> {
    match value {
        serde_json::Value::Number(n) => n
            .as_u64()
            .map(alloy_primitives::U256::from)
            .ok_or_else(|| Error::AbiEncode("number too large for u64, use string".into())),
        serde_json::Value::String(s) => {
            let s = s.trim();
            s.strip_prefix("0x").map_or_else(
                || {
                    alloy_primitives::U256::from_str_radix(s, 10)
                        .map_err(|e| Error::AbiEncode(format!("invalid uint256: {e}")))
                },
                |hex_str| {
                    alloy_primitives::U256::from_str_radix(hex_str, 16)
                        .map_err(|e| Error::AbiEncode(format!("invalid hex uint256: {e}")))
                },
            )
        }
        _ => Err(Error::AbiEncode(
            "expected number or string for uint256".into(),
        )),
    }
}

fn parse_int256(value: &serde_json::Value) -> Result<alloy_primitives::I256> {
    match value {
        serde_json::Value::Number(n) => n
            .as_i64()
            .ok_or_else(|| Error::AbiEncode("number too large, use string".into()))
            .and_then(|i| {
                alloy_primitives::I256::try_from(i)
                    .map_err(|e| Error::AbiEncode(format!("invalid int256: {e}")))
            }),
        serde_json::Value::String(s) => s
            .trim()
            .parse::<alloy_primitives::I256>()
            .map_err(|e| Error::AbiEncode(format!("invalid int256: {e}"))),
        _ => Err(Error::AbiEncode(
            "expected number or string for int256".into(),
        )),
    }
}

fn parse_uint_generic<T: std::str::FromStr + TryFrom<u64>>(value: &serde_json::Value) -> Result<T>
where
    <T as std::str::FromStr>::Err: std::fmt::Display,
    <T as TryFrom<u64>>::Error: std::fmt::Display,
{
    match value {
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| Error::AbiEncode("invalid number".into()))
            .and_then(|u| {
                T::try_from(u)
                    .map_err(|e| Error::AbiEncode(format!("number conversion error: {e}")))
            }),
        serde_json::Value::String(s) => s
            .parse::<T>()
            .map_err(|e| Error::AbiEncode(format!("invalid number: {e}"))),
        _ => Err(Error::AbiEncode("expected number or string".into())),
    }
}
