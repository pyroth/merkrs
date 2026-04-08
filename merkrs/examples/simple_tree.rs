#![allow(
    clippy::print_stdout,
    clippy::indexing_slicing,
    unused_crate_dependencies,
    reason = "example"
)]
//! Simple Merkle Tree example.
//!
//! Demonstrates basic usage of `SimpleMerkleTree` for bytes32 values.
//!
//! Run: `cargo run --example simple_tree`

use merkrs::bytes::encode_hex;
use merkrs::{Bytes32, SimpleMerkleTree, simple};

fn main() -> merkrs::Result<()> {
    let values: Vec<Bytes32> = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

    let tree = SimpleMerkleTree::new(&values, simple::Options::default())?;

    println!("Root: {}", encode_hex(tree.root()));
    println!("Tree size: {} leaves\n", tree.len());

    println!("Tree structure:");
    println!("{}\n", tree.render()?);

    for (i, value) in tree.entries() {
        let proof = tree.proof_by_index(i)?;
        let valid = tree.verify_proof_by_index(i, &proof)?;

        println!("Leaf {i}: {}", encode_hex(value));
        println!(
            "  Proof: {:?}",
            proof.iter().map(encode_hex).collect::<Vec<_>>()
        );
        println!("  Valid: {valid}\n");
    }

    let proof = tree.proof(&values[0])?;
    let valid = SimpleMerkleTree::verify(tree.root(), &values[0], &proof, None);
    println!("Static verification: {valid}");

    Ok(())
}
