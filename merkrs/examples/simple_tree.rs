//! Simple Merkle Tree example.
//!
//! Demonstrates basic usage of `SimpleMerkleTree` for bytes32 values.
//!
//! Run: `cargo run --example simple_tree`

use merkrs::{Bytes32, SimpleMerkleTree, SimpleMerkleTreeOptions};

fn main() -> merkrs::Result<()> {
    // Create leaf values (bytes32)
    let values: Vec<Bytes32> = vec![
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        [4u8; 32],
    ];

    // Build the tree
    let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default())?;

    println!("Root: {}", tree.root());
    println!("Tree size: {} leaves\n", tree.len());

    // Render tree structure
    println!("Tree structure:");
    println!("{}\n", tree.render()?);

    // Generate and verify proof for each leaf
    for (i, value) in tree.entries() {
        let proof = tree.get_proof_by_index(i)?;
        let valid = tree.verify_proof_by_index(i, &proof)?;

        println!("Leaf {}: {}", i, value);
        println!("  Proof: {:?}", proof);
        println!("  Valid: {}\n", valid);
    }

    // Static verification (without tree instance)
    let proof = tree.get_proof(&values[0])?;
    let valid = SimpleMerkleTree::verify(tree.root(), &values[0], &proof, None)?;
    println!("Static verification: {}", valid);

    Ok(())
}
