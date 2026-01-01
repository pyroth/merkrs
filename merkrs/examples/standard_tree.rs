//! Standard Merkle Tree example - Airdrop scenario.
//!
//! Demonstrates `StandardMerkleTree` with Solidity ABI encoding,
//! commonly used for token airdrops and allowlists.
//!
//! Run: `cargo run --example standard_tree`

use merkrs::{MerkleTreeOptions, StandardMerkleTree};
use serde_json::json;

fn main() -> merkrs::Result<()> {
    // Airdrop data: (address, amount)
    let recipients = vec![
        vec![json!("0x1111111111111111111111111111111111111111"), json!(1000)],
        vec![json!("0x2222222222222222222222222222222222222222"), json!(2500)],
        vec![json!("0x3333333333333333333333333333333333333333"), json!(500)],
        vec![json!("0x4444444444444444444444444444444444444444"), json!(750)],
    ];

    // Build tree with Solidity types
    let tree = StandardMerkleTree::of(
        recipients.clone(),
        vec!["address".to_string(), "uint256".to_string()],
        MerkleTreeOptions::default(),
    )?;

    println!("=== Airdrop Merkle Tree ===\n");
    println!("Root: {}", tree.root());
    println!("Recipients: {}\n", tree.len());

    // Generate proof for a specific recipient
    let recipient = &recipients[1];
    let proof = tree.get_proof(recipient)?;

    println!("Recipient: {} -> {} tokens", recipient[0], recipient[1]);
    println!("Proof:");
    for (i, hash) in proof.iter().enumerate() {
        println!("  [{}] {}", i, hash);
    }

    // Verify the proof
    let valid = tree.verify_proof(recipient, &proof)?;
    println!("\nProof valid: {}", valid);

    // Static verification (for smart contract integration)
    let valid = StandardMerkleTree::verify(
        tree.root(),
        &["address".to_string(), "uint256".to_string()],
        recipient,
        &proof,
    )?;
    println!("Static verification: {}", valid);

    // Render tree
    println!("\n=== Tree Structure ===\n");
    println!("{}", tree.render()?);

    Ok(())
}
