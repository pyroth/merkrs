# merkrs

**A Rust library to generate merkle trees and merkle proofs.**

Well suited for airdrops and similar mechanisms in combination with Solidity [`OpenZeppelin MerkleProof`] utilities.

[`OpenZeppelin MerkleProof`]: https://docs.openzeppelin.com/contracts/4.x/api/utils#MerkleProof

[![Crates.io](https://img.shields.io/crates/v/merkrs.svg)](https://crates.io/crates/merkrs)
[![Documentation](https://docs.rs/merkrs/badge.svg)](https://docs.rs/merkrs)

## Quick Start

```bash
cargo add merkrs
```

### Building a Tree

```rust
use merkrs::{StandardMerkleTree, MerkleTreeOptions};
use serde_json::json;

let values = vec![
    vec![json!("0x1111111111111111111111111111111111111111"), json!("5000000000000000000")],
    vec![json!("0x2222222222222222222222222222222222222222"), json!("2500000000000000000")],
];

let tree = StandardMerkleTree::of(
    values.clone(),
    vec!["address".to_string(), "uint256".to_string()],
    MerkleTreeOptions::default(),
).unwrap();

println!("Root: {}", tree.root());

// Serialize for distribution
let data = tree.dump();
let json = serde_json::to_string_pretty(&data).unwrap();
std::fs::write("tree.json", json).unwrap();
```

### Obtaining a Proof

```rust
use merkrs::{StandardMerkleTree, StandardTreeData};
use serde_json::json;

// Load tree
let json_data = std::fs::read_to_string("tree.json").unwrap();
let data: StandardTreeData = serde_json::from_str(&json_data).unwrap();
let tree = StandardMerkleTree::load(data).unwrap();

// Get proof by value
let proof = tree.get_proof(&vec![
    json!("0x1111111111111111111111111111111111111111"),
    json!("5000000000000000000")
]).unwrap();

println!("Proof: {:?}", proof);
```

### Validating a Proof in Solidity

Once the proof has been generated, it can be validated in Solidity using [`OpenZeppelin MerkleProof`] as in the following example:

```solidity
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract Verifier {
    bytes32 private root;

    constructor(bytes32 _root) {
        // (1)
        root = _root;
    }

    function verify(
        bytes32[] memory proof,
        address addr,
        uint256 amount
    ) public {
        // (2)
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(addr, amount))));
        // (3)
        require(MerkleProof.verify(proof, root, leaf), "Invalid proof");
        // (4)
        // ...
    }
}
```

1. Store the tree root in your contract.
2. Compute the [leaf hash](#leaf-hash) for the provided `addr` and `amount` ABI encoded values.
3. Verify it using [`OpenZeppelin MerkleProof`]'s `verify` function.
4. Use the verification to make further operations on the contract. (Consider you may want to add a mechanism to prevent reuse of a leaf).

## Standard Merkle Trees

This library works on "standard" merkle trees designed for Ethereum smart contracts. We have defined them with a few characteristics that make them secure and good for on-chain verification.

- The tree is shaped as a [complete binary tree](https://xlinux.nist.gov/dads/HTML/completeBinaryTree.html).
- The leaves are sorted.
- The leaves are the result of ABI encoding a series of values.
- The hash used is Keccak256.
- The leaves are double-hashed[^1] to prevent [second preimage attacks].

[second preimage attacks]: https://flawed.net.nz/2018/02/21/attacking-merkle-trees-with-a-second-preimage-attack/

## Simple Merkle Trees

The library also supports "simple" merkle trees, which are a simplified version of the standard ones. They are designed to be more flexible and accept arbitrary `[u8; 32]` data as leaves. It keeps the same tree shape and internal pair hashing algorithm.

As opposed to standard trees, leaves are not double-hashed. Instead they are hashed once and then hashed in pairs inside the tree. This is useful to override the leaf hashing algorithm and use a different one prior to building the tree.

Users of tooling that produced trees without double leaf hashing can use this feature to build a representation of the tree in Rust. We recommend this approach exclusively for trees that are already built on-chain. Otherwise the standard tree may be a better fit.

```rust
use merkrs::{SimpleMerkleTree, SimpleMerkleTreeOptions, Bytes32, keccak256};

let values: Vec<Bytes32> = vec![
    keccak256(b"Value 1"),
    keccak256(b"Value 2"),
];

let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default()).unwrap();
// SimpleMerkleTree shares the same API as StandardMerkleTree
```

## Advanced Usage

### Leaf Hash

The Standard Merkle Tree uses an opinionated double leaf hashing algorithm. For example, a leaf in the tree with value `[addr, amount]` can be computed in Solidity as follows:

```solidity
bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(addr, amount))));
```

This is an opinionated design that we believe will offer the best out of the box experience for most users. However, there are advanced use cases where a different leaf hashing algorithm may be needed. For those, the `SimpleMerkleTree` can be used to build a tree with custom leaf hashing.

### Leaf Ordering

Each leaf of a merkle tree can be proven individually. The relative ordering of leaves is mostly irrelevant when the only objective is to prove the inclusion of individual leaves in the tree. Proving multiple leaves at once is however a little bit more difficult.

This library proposes a mechanism to prove (and verify) that sets of leaves are included in the tree. These "multiproofs" can also be verified onchain using the implementation available in `@openzeppelin/contracts`. This mechanism requires the leaves to be ordered respective to their position in the tree. For example, if the tree leaves are (in hex form) `[ 0xAA...AA, 0xBB...BB, 0xCC...CC, 0xDD...DD]`, then you'd be able to prove `[0xBB...BB, 0xDD...DD]` as a subset of the leaves, but not `[0xDD...DD, 0xBB...BB]`.

Since this library knows the entire tree, you can generate a multiproof with the requested leaves in any order. The library will re-order them so that they appear inside the proof in the correct order. The `MultiProof` object returned by `tree.get_multi_proof_by_indices(...)` will have the leaves ordered according to their position in the tree, and not in the order in which you provided them.

By default, the library orders the leaves according to their hash when building the tree. This is so that a smart contract can build the hashes of a set of leaves and order them correctly without any knowledge of the tree itself. Said differently, it is simpler for a smart contract to process a multiproof for leaves that it rebuilt itself if the corresponding tree is ordered.

However, some trees are constructed iteratively from unsorted data, causing the leaves to be unsorted as well. For this library to be able to represent such trees, the call to `StandardMerkleTree::of` includes an option to disable sorting. Using that option, the leaves are kept in the order in which they were provided. Note that this option has no effect on your ability to generate and verify proofs and multiproofs in Rust, but that it may introduce challenges when verifying multiproofs onchain. We recommend only using it for building a representation of trees that are built (onchain) using an iterative process.

## Supported Types (StandardMerkleTree)

- `address`
- `uint256`, `uint128`, `uint64`, `uint32`, `uint16`, `uint8`
- `int256`
- `bytes32`
- `bytes`
- `bool`
- `string`

## Examples

See the [`examples/`](./merkrs/examples) directory for complete working examples:

- [`serialization.rs`](./merkrs/examples/serialization.rs) - Standard Merkle Tree with ABI-encoded values and serialization

## License

This project is licensed under either of the following licenses, at your option:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or [https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0))
- MIT license ([LICENSE-MIT](LICENSE-MIT) or [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT))

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any additional terms or conditions.

[^1]: The underlying reason for hashing the leaves twice is to prevent the leaf values from being 64 bytes long _prior_ to hashing. Otherwise, the concatenation of a sorted pair of internal nodes in the Merkle tree could be reinterpreted as a leaf value. See [OpenZeppelin issue #3091](https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3091) for more details.
