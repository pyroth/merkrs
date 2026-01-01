//! Serialization example.
//!
//! Demonstrates how to dump and load Merkle trees for persistence.
//!
//! Run: `cargo run --example serialization`

use merkrs::{
    Bytes32, MerkleTreeOptions, SimpleMerkleTree, SimpleMerkleTreeData,
    SimpleMerkleTreeOptions, StandardMerkleTree, StandardMerkleTreeData,
};
use serde_json::json;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    println!("=== SimpleMerkleTree Serialization ===\n");
    simple_tree_example()?;

    println!("\n=== StandardMerkleTree Serialization ===\n");
    standard_tree_example()?;

    Ok(())
}

fn simple_tree_example() -> Result<()> {
    // Create tree
    let values: Vec<Bytes32> = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default())?;

    println!("Original root: {}", tree.root());

    // Dump to JSON
    let data = tree.dump();
    let json_str = serde_json::to_string_pretty(&data)?;

    println!("\nSerialized JSON:\n{}", json_str);

    // Load from JSON
    let loaded_data: SimpleMerkleTreeData = serde_json::from_str(&json_str)?;
    let loaded_tree = SimpleMerkleTree::load(loaded_data, None)?;

    println!("\nLoaded root: {}", loaded_tree.root());
    println!("Roots match: {}", tree.root() == loaded_tree.root());

    // Verify proofs still work after loading
    let proof = loaded_tree.get_proof(&values[0])?;
    let valid = loaded_tree.verify_proof(&values[0], &proof)?;
    println!("Proof verification after load: {}", valid);

    Ok(())
}

fn standard_tree_example() -> Result<()> {
    // Create airdrop tree
    let recipients = vec![
        vec![json!("0x1111111111111111111111111111111111111111"), json!(1000)],
        vec![json!("0x2222222222222222222222222222222222222222"), json!(2000)],
    ];

    let tree = StandardMerkleTree::of(
        recipients.clone(),
        vec!["address".to_string(), "uint256".to_string()],
        MerkleTreeOptions::default(),
    )?;

    println!("Original root: {}", tree.root());

    // Dump to JSON (suitable for file storage)
    let data = tree.dump();
    let json_str = serde_json::to_string_pretty(&data)?;

    println!("\nSerialized JSON:\n{}", json_str);

    // Load from JSON
    let loaded_data: StandardMerkleTreeData = serde_json::from_str(&json_str)?;
    let loaded_tree = StandardMerkleTree::load(loaded_data)?;

    println!("\nLoaded root: {}", loaded_tree.root());
    println!("Roots match: {}", tree.root() == loaded_tree.root());

    // Enumerate all entries after loading
    println!("\nLoaded entries:");
    for (i, value) in loaded_tree.entries() {
        println!("  [{}] {} -> {}", i, value[0], value[1]);
    }

    Ok(())
}
