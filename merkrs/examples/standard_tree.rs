#![allow(
    clippy::print_stdout,
    clippy::indexing_slicing,
    clippy::shadow_unrelated,
    unused_crate_dependencies,
    reason = "example"
)]
//! Standard Merkle Tree example - Airdrop scenario.
//!
//! Demonstrates `StandardMerkleTree` with Solidity ABI encoding,
//! commonly used for token airdrops and allowlists.
//!
//! Run: `cargo run --example standard_tree`

use merkrs::bytes::encode_hex;
use merkrs::{StandardMerkleTree, standard};
use serde_json::json;

fn main() -> merkrs::Result<()> {
    let recipients = vec![
        vec![
            json!("0x1111111111111111111111111111111111111111"),
            json!(1000),
        ],
        vec![
            json!("0x2222222222222222222222222222222222222222"),
            json!(2500),
        ],
        vec![
            json!("0x3333333333333333333333333333333333333333"),
            json!(500),
        ],
        vec![
            json!("0x4444444444444444444444444444444444444444"),
            json!(750),
        ],
    ];

    let enc: Vec<String> = vec!["address".into(), "uint256".into()];
    let tree = StandardMerkleTree::new(
        recipients.clone(),
        enc.clone(),
        standard::Options::default(),
    )?;

    println!("=== Airdrop Merkle Tree ===\n");
    println!("Root: {}", encode_hex(tree.root()));
    println!("Recipients: {}\n", tree.len());

    let recipient = &recipients[1];
    let proof = tree.proof(recipient)?;

    println!("Recipient: {} -> {} tokens", recipient[0], recipient[1]);
    println!("Proof:");
    for (i, hash) in proof.iter().enumerate() {
        println!("  [{i}] {}", encode_hex(hash));
    }

    let valid = tree.verify_proof(recipient, &proof)?;
    println!("\nProof valid: {valid}");

    let valid = StandardMerkleTree::verify(tree.root(), &enc, recipient, &proof)?;
    println!("Static verification: {valid}");

    println!("\n=== Tree Structure ===\n");
    println!("{}", tree.render()?);

    Ok(())
}
