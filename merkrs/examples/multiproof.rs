//! Multi-proof example.
//!
//! Demonstrates generating and verifying proofs for multiple leaves
//! simultaneously, which is more gas-efficient on-chain.
//!
//! Run: `cargo run --example multiproof`

use merkrs::{Bytes32, SimpleMerkleTree, SimpleMerkleTreeOptions};

fn main() -> merkrs::Result<()> {
    // Create a tree with 8 leaves
    let values: Vec<Bytes32> = (0..8)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[31] = i;
            bytes
        })
        .collect();

    let tree = SimpleMerkleTree::of(&values, SimpleMerkleTreeOptions::default())?;

    println!("=== Multi-Proof Example ===\n");
    println!("Root: {}", tree.root());
    println!("Total leaves: {}\n", tree.len());

    // Generate multi-proof for indices [0, 2, 5]
    let indices = vec![0, 2, 5];
    let multiproof = tree.get_multi_proof_by_indices(&indices)?;

    println!("Proving leaves at indices: {:?}\n", indices);

    println!("MultiProof:");
    println!("  Leaves ({}):", multiproof.leaves.len());
    for leaf in &multiproof.leaves {
        println!("    {}", leaf);
    }

    println!("  Proof ({}):", multiproof.proof.len());
    for hash in &multiproof.proof {
        println!("    {}", hash);
    }

    println!("  Proof flags: {:?}", multiproof.proof_flags);

    // Verify multi-proof
    let valid = SimpleMerkleTree::verify_multi_proof(tree.root(), &multiproof, None)?;
    println!("\nMulti-proof valid: {}", valid);

    // Compare with individual proofs
    println!("\n=== Comparison with Individual Proofs ===");
    let mut total_individual_hashes = 0;
    for &i in &indices {
        let proof = tree.get_proof_by_index(i)?;
        total_individual_hashes += proof.len();
    }

    println!("Individual proofs total hashes: {}", total_individual_hashes);
    println!("Multi-proof hashes: {}", multiproof.proof.len());
    println!(
        "Savings: {} hashes ({:.0}% reduction)",
        total_individual_hashes - multiproof.proof.len(),
        (1.0 - multiproof.proof.len() as f64 / total_individual_hashes as f64) * 100.0
    );

    Ok(())
}
