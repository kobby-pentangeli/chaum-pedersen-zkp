use std::time::Instant;

use chaum_pedersen::{BatchVerifier, OsRng, Parameters, Prover, Scalar, Transcript, Witness};

fn main() {
    println!("Chaum-Pedersen Zero-Knowledge Protocol: Batch Verification Example");
    println!("==========================================\n");

    let mut rng = OsRng;
    let params = Parameters::new();

    println!("Generating 10 proofs...");
    let batch_size = 10;
    let mut batch_verifier = BatchVerifier::new();

    for i in 0..batch_size {
        let x = Scalar::random(&mut rng);
        let witness = Witness::new(x).unwrap();
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
    println!("\nFor verification-throughput numbers, run the benchmarks:");
    println!("  cargo bench --bench batch_verification");
}
