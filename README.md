<!-- markdownlint-disable MD033 MD041 MD036 -->

# Merkrs

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![CI][ci-badge]][ci-url]
[![License][license-badge]][license-url]
[![Rust][rust-badge]][rust-url]

[crates-badge]: https://img.shields.io/crates/v/merkrs.svg
[crates-url]: https://crates.io/crates/merkrs
[docs-badge]: https://img.shields.io/docsrs/merkrs.svg
[docs-url]: https://docs.rs/merkrs
[ci-badge]: https://github.com/qntx/merkrs/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/qntx/merkrs/actions/workflows/ci.yml
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg
[license-url]: LICENSE-MIT
[rust-badge]: https://img.shields.io/badge/rust-edition%202024-orange.svg
[rust-url]: https://doc.rust-lang.org/edition-guide/

**Rust library for generating merkle trees and merkle proofs — Keccak256-based, Solidity-compatible, airdrop-ready.**

Well suited for airdrops and allowlists in combination with Solidity [OpenZeppelin MerkleProof] utilities. Supports standard (ABI-encoded, double-hashed) and simple (raw `[u8; 32]`) tree modes, multiproofs, and full serialization.

[OpenZeppelin MerkleProof]: https://docs.openzeppelin.com/contracts/4.x/api/utils#MerkleProof

## Quick Start

```bash
cargo add merkrs
```

### Building a Tree

```rust
use merkrs::{StandardMerkleTree, standard, bytes::encode_hex};
use serde_json::json;

fn main() -> merkrs::Result<()> {
    let values = vec![
        vec![json!("0x1111111111111111111111111111111111111111"), json!("5000000000000000000")],
        vec![json!("0x2222222222222222222222222222222222222222"), json!("2500000000000000000")],
    ];

    let tree = StandardMerkleTree::new(
        values,
        vec!["address".into(), "uint256".into()],
        standard::Options::default(),
    )?;

    println!("Root: {}", encode_hex(tree.root()));

    let data = tree.to_data();
    let json = serde_json::to_string_pretty(&data).expect("serialising tree data cannot fail");
    std::fs::write("tree.json", json).expect("disk write");
    Ok(())
}
```

### Obtaining a Proof

```rust
use merkrs::{StandardMerkleTree, StandardMerkleTreeData};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let json_data = std::fs::read_to_string("tree.json")?;
    let data: StandardMerkleTreeData = serde_json::from_str(&json_data)?;
    let tree = StandardMerkleTree::from_data(data)?;

    let proof = tree.proof(&vec![
        json!("0x1111111111111111111111111111111111111111"),
        json!("5000000000000000000"),
    ])?;

    println!("Proof: {proof:?}");
    Ok(())
}
```

### Validating a Proof in Solidity

Once the proof has been generated, it can be validated in Solidity using [OpenZeppelin MerkleProof]:

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
3. Verify it using [OpenZeppelin MerkleProof]'s `verify` function.
4. Use the verification to make further operations on the contract. (Consider you may want to add a mechanism to prevent reuse of a leaf).

## Design

- **Standard trees** — ABI-encoded leaves, Keccak256 hashing, double-hashed[^1] to prevent [second preimage attacks], sorted for deterministic on-chain verification
- **Simple trees** — Arbitrary `[u8; 32]` leaves, single-hashed, flexible for custom leaf hashing algorithms
- **Multiproofs** — Prove multiple leaves in a single proof, compatible with OpenZeppelin's on-chain verification
- **Serialization** — Full tree serialization / deserialization via `serde` for distribution and storage
- **Complete binary tree** — [Standard shape](https://xlinux.nist.gov/dads/HTML/completeBinaryTree.html) with sorted leaves for secure on-chain verification
- **Strict linting** — Clippy `pedantic` + `nursery` + `correctness` (deny), zero warnings

[second preimage attacks]: https://flawed.net.nz/2018/02/21/attacking-merkle-trees-with-a-second-preimage-attack/

## Simple Merkle Trees

The library also supports "simple" merkle trees, which accept arbitrary `[u8; 32]` data as leaves. They keep the same tree shape and internal pair hashing algorithm but without double leaf hashing.

This is useful to override the leaf hashing algorithm and use a different one prior to building the tree. We recommend this approach exclusively for trees that are already built on-chain. Otherwise the standard tree may be a better fit.

```rust
use merkrs::{SimpleMerkleTree, simple, Bytes32, keccak256};

fn main() -> merkrs::Result<()> {
    let values: Vec<Bytes32> = vec![keccak256(b"Value 1"), keccak256(b"Value 2")];
    let tree = SimpleMerkleTree::new(&values, simple::Options::default())?;
    let _ = tree.root();
    Ok(())
}
```

## Advanced Usage

### Leaf Hash

The Standard Merkle Tree uses an opinionated double leaf hashing algorithm. For example, a leaf in the tree with value `[addr, amount]` can be computed in Solidity as follows:

```solidity
bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(addr, amount))));
```

For use cases where a different leaf hashing algorithm is needed, the `SimpleMerkleTree` can be used to build a tree with custom leaf hashing.

### Leaf Ordering

Each leaf of a merkle tree can be proven individually. The relative ordering of leaves is mostly irrelevant when the only objective is to prove the inclusion of individual leaves in the tree. Proving multiple leaves at once is however a little bit more difficult.

This library proposes a mechanism to prove (and verify) that sets of leaves are included in the tree. These "multiproofs" can also be verified onchain using the implementation available in `@openzeppelin/contracts`. This mechanism requires the leaves to be ordered respective to their position in the tree. For example, if the tree leaves are (in hex form) `[ 0xAA...AA, 0xBB...BB, 0xCC...CC, 0xDD...DD]`, then you'd be able to prove `[0xBB...BB, 0xDD...DD]` as a subset of the leaves, but not `[0xDD...DD, 0xBB...BB]`.

Since this library knows the entire tree, you can generate a multiproof with the requested leaves in any order. The library will re-order them so that they appear inside the proof in the correct order. The `MultiProof` object returned by `tree.multi_proof_by_indices(...)` will have the leaves ordered according to their position in the tree, and not in the order in which you provided them.

By default, the library orders the leaves according to their hash when building the tree. This is so that a smart contract can build the hashes of a set of leaves and order them correctly without any knowledge of the tree itself.

However, some trees are constructed iteratively from unsorted data, causing the leaves to be unsorted as well. For this library to be able to represent such trees, the call to `StandardMerkleTree::new` includes an option to disable sorting. Using that option, the leaves are kept in the order in which they were provided. Note that this option has no effect on your ability to generate and verify proofs and multiproofs in Rust, but that it may introduce challenges when verifying multiproofs onchain. We recommend only using it for building a representation of trees that are built (onchain) using an iterative process.

## Supported Types (StandardMerkleTree)

| Type | Example |
| --- | --- |
| `address` | `"0x1111...1111"` |
| `uint256` / `uint128` / `uint64` / `uint32` / `uint16` / `uint8` | `"5000000000000000000"` |
| `int256` | `"-1"` |
| `bytes32` | `"0xabcd...ef01"` |
| `bytes` | `"0xdeadbeef"` |
| `bool` | `true` |
| `string` | `"hello"` |

## Examples

See the [`examples/`](./merkrs/examples) directory for complete working examples:

- **[`simple_tree.rs`](./merkrs/examples/simple_tree.rs)** — Simple Merkle Tree construction, proofs, and verification
- **[`standard_tree.rs`](./merkrs/examples/standard_tree.rs)** — Standard Merkle Tree with ABI-encoded Solidity values
- **[`multiproof.rs`](./merkrs/examples/multiproof.rs)** — Multi-proof generation and verification
- **[`serialization.rs`](./merkrs/examples/serialization.rs)** — Tree serialization and deserialization

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual-licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QuantX](https://qntx.org)** open-source project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
