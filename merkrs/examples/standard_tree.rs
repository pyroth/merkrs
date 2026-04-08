//! Standard Merkle Tree example - Airdrop scenario.
//!
//! Demonstrates `StandardMerkleTree` with Solidity ABI encoding,
//! commonly used for token airdrops and allowlists.
//!
//! Run: `cargo run --example standard_tree`

use merkrs::bytes::bytes_to_hex;
use merkrs::{StandardMerkleTree, standard};
use serde_json::json;

fn main() -> merkrs::Result<()> {
    let recipients = vec![
        vec![json!("0x1111111111111111111111111111111111111111"), json!(1000)],
        vec![json!("0x2222222222222222222222222222222222222222"), json!(2500)],
        vec![json!("0x3333333333333333333333333333333333333333"), json!(500)],
        vec![json!("0x4444444444444444444444444444444444444444"), json!(750)],
    ];

    let tree = StandardMerkleTree::of(
        recipients.clone(),
        vec!["address".into(), "uint256".into()],
        standard::Options::default(),
    )?;

    println!("=== Airdrop Merkle Tree ===\n");
    println!("Root: {}", bytes_to_hex(tree.root()));
    println!("Recipients: {}\n", tree.leaf_count());

    let recipient = &recipients[1];
    let proof = tree.get_proof(recipient)?;

    println!("Recipient: {} -> {} tokens", recipient[0], recipient[1]);
    println!("Proof:");
    for (i, hash) in proof.iter().enumerate() {
        println!("  [{i}] {}", bytes_to_hex(hash));
    }

    let valid = tree.verify_proof(recipient, &proof)?;
    println!("\nProof valid: {valid}");

    let enc: Vec<String> = vec!["address".into(), "uint256".into()];
    let valid = StandardMerkleTree::verify(tree.root(), &enc, recipient, &proof)?;
    println!("Static verification: {valid}");

    println!("\n=== Tree Structure ===\n");
    println!("{}", tree.render()?);

    Ok(())
}
