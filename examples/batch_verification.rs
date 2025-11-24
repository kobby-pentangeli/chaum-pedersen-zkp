use std::time::Instant;

use chaum_pedersen::{
    BatchVerifier, Parameters, Prover, Ristretto255, SecureRng, Transcript, Witness,
};

fn main() {
    println!("Chaum-Pedersen Zero-Knowledge Protocol: Batch Verification Example");
    println!("==========================================\n");

    let mut rng = SecureRng::new();
    let params = Parameters::new();

    println!("Generating 10 proofs...");
    let batch_size = 10;
    let mut batch_verifier = BatchVerifier::new();

    for i in 0..batch_size {
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);
        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();

        let context = format!("user-{i}-session");
        let mut transcript = Transcript::new();
        transcript.append_context(context.as_bytes());
        let proof = prover
            .prove_with_transcript(&mut rng, &mut transcript)
            .unwrap();

        batch_verifier
            .add_with_context(params.clone(), statement, proof, Some(context.into_bytes()))
            .unwrap();

        println!("  Added proof {} to batch", i + 1);
    }

    println!("\nBatch contains {} proofs", batch_verifier.len());
    println!(
        "Remaining capacity: {}",
        batch_verifier.remaining_capacity()
    );

    println!("\nVerifying all proofs in batch...");
    let start = Instant::now();
    let results = batch_verifier.verify(&mut rng).unwrap();
    let duration = start.elapsed();

    println!("Batch verification completed in {duration:?}");
    println!("\nResults:");
    for (i, result) in results.iter().enumerate() {
        let status = if result.is_ok() { "VALID" } else { "INVALID" };
        println!("  Proof {}: {}", i + 1, status);
    }

    let valid_count = results.iter().filter(|r| r.is_ok()).count();
    println!("\nSummary: {}/{} proofs are valid", valid_count, batch_size);

    println!("\n--- Performance Comparison ---");
    println!("Comparing batch verification vs individual verification...\n");

    let mut individual_proofs = Vec::new();
    for _ in 0..batch_size {
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);
        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();
        let proof = prover.prove(&mut rng).unwrap();
        let verifier = chaum_pedersen::Verifier::new(params.clone(), statement);
        individual_proofs.push((verifier, proof));
    }

    let start = Instant::now();
    for (verifier, proof) in &individual_proofs {
        verifier.verify(proof).unwrap();
    }
    let individual_duration = start.elapsed();

    let mut batch_verifier = BatchVerifier::new();
    for _ in 0..batch_size {
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);
        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();
        let proof = prover.prove(&mut rng).unwrap();
        batch_verifier
            .add(params.clone(), statement, proof)
            .unwrap();
    }

    let start = Instant::now();
    batch_verifier.verify(&mut rng).unwrap();
    let batch_duration = start.elapsed();

    println!("Individual verification: {:?}", individual_duration);
    println!("Batch verification:      {:?}", batch_duration);

    let speedup = individual_duration.as_nanos() as f64 / batch_duration.as_nanos() as f64;
    println!("Speedup: {:.2}x faster", speedup);

    if speedup > 1.0 {
        let improvement = ((speedup - 1.0) * 100.0) as i32;
        println!("Performance improvement: ~{}%", improvement);
    }
}
