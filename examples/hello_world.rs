//! Basic usage example of the Chaum-Pedersen zero-knowledge protocol.
//!
//! This example demonstrates:
//! - Creating protocol parameters
//! - Generating a secret witness
//! - Computing the public statement
//! - Generating a zero-knowledge proof
//! - Verifying the proof

use chaum_pedersen::{
    Group, Parameters, Proof, Prover, Ristretto255, SecureRng, Statement, Transcript, Verifier,
    Witness,
};

fn main() {
    println!("Chaum-Pedersen Zero-Knowledge Protocol: Basic Example\n");

    println!("Step 1: Initialize parameters and RNG");
    let params = Parameters::<Ristretto255>::new();
    let mut rng = SecureRng::new();
    println!("  Using Ristretto255 group with default generators\n");

    println!("Step 2: Prover generates secret witness");
    let x = Ristretto255::random_scalar(&mut rng);
    let witness = Witness::new(x);
    println!("  Secret witness generated (automatically zeroized on drop)\n");

    println!("Step 3: Compute public statement from witness");
    let statement = Statement::from_witness(&params, &witness);
    println!("  Statement computed: y1 = g^x, y2 = h^x");
    println!("  (The secret x remains hidden)\n");

    println!("Step 4: Generate zero-knowledge proof");
    let mut prover_transcript = Transcript::new();
    let prover = Prover::new(params.clone(), witness);
    let proof = prover
        .prove_with_transcript(&mut rng, &mut prover_transcript)
        .expect("Proof generation should succeed");
    println!("  Proof generated using Fiat-Shamir transform\n");

    println!("Step 5: Serialize proof for transmission");
    let proof_bytes = proof.to_bytes().expect("Serialization should succeed");
    println!("  Proof size: {} bytes\n", proof_bytes.len());

    println!("Step 6: Deserialize proof");
    let received_proof =
        Proof::<Ristretto255>::from_bytes(&proof_bytes).expect("Deserialization should succeed");
    println!("  Proof deserialized successfully\n");

    println!("Step 7: Verify the proof");
    let mut verifier_transcript = Transcript::new();
    let verifier = Verifier::new(params, statement);
    match verifier.verify_with_transcript(&received_proof, &mut verifier_transcript) {
        Ok(()) => println!("  Proof is VALID"),
        Err(e) => println!("  Proof is INVALID: {}", e),
    }

    println!("\nProof verified successfully!");
    println!("The verifier is convinced that the prover knows x");
    println!("without learning anything about the value of x.");
}
