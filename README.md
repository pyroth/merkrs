# merkrs

Rust implementation of Merkle tree library, compatible with [OpenZeppelin's JavaScript](https://github.com/OpenZeppelin/merkle-tree.git) implementation.

## Features

- **StandardMerkleTree**: For structured data with ABI encoding (compatible with Solidity)
- **SimpleMerkleTree**: For simple bytes32 values
- Full proof generation and verification
- Multi-proof support
- Serialization/deserialization with serde
- Keccak256 hashing (Ethereum compatible)

## Usage

### StandardMerkleTree

For structured data like airdrop lists:

```rust
use merkrs::{StandardMerkleTree, MerkleTreeOptions};
use serde_json::json;

let values = vec![
    vec![json!("0x1111111111111111111111111111111111111111"), json!(100u64)],
    vec![json!("0x2222222222222222222222222222222222222222"), json!(200u64)],
];

let tree = StandardMerkleTree::of(
    values.clone(),
    vec!["address".to_string(), "uint256".to_string()],
    MerkleTreeOptions::default(),
).unwrap();

// Get root
println!("Root: {}", tree.root());

// Generate proof
let proof = tree.get_proof(&values[0]).unwrap();

// Verify proof
assert!(tree.verify_proof(&values[0], &proof).unwrap());

// Dump and load
let data = tree.dump();
let json = serde_json::to_string(&data).unwrap();
```

### SimpleMerkleTree

For simple bytes32 values:

```rust
use merkrs::{SimpleMerkleTree, SimpleMerkleTreeOptions, Bytes32};

let values: Vec<Bytes32> = vec![
    [0u8; 32],
    [1u8; 32],
    [2u8; 32],
    [3u8; 32],
];

let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();

// Get root
println!("Root: {}", tree.root());

// Generate and verify proof
let proof = tree.get_proof(&values[0]).unwrap();
assert!(tree.verify_proof(&values[0], &proof).unwrap());

// Static verification (without tree instance)
let verified = SimpleMerkleTree::verify(tree.root(), &values[0], &proof, None).unwrap();
assert!(verified);
```

### Multi-proofs

```rust
let indices = vec![0, 2];
let multiproof = tree.get_multi_proof_by_indices(&indices).unwrap();

// Verify multi-proof
let verified = SimpleMerkleTree::verify_multi_proof(tree.root(), &multiproof, None).unwrap();
assert!(verified);
```

## Supported Types (StandardMerkleTree)

- `address`
- `uint256`, `uint128`, `uint64`, `uint32`, `uint16`, `uint8`
- `int256`
- `bytes32`
- `bytes`
- `bool`
- `string`

## Compatibility

This library produces Merkle trees compatible with:

- OpenZeppelin's `@openzeppelin/merkle-tree` JavaScript library
- OpenZeppelin Solidity contracts for on-chain verification

## License

This project is licensed under either of the following licenses, at your option:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or [https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0))
- MIT license ([LICENSE-MIT](LICENSE-MIT) or [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT))

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any additional terms or conditions.
