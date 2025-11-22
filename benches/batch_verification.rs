use std::hint::black_box;

use chaum_pedersen::{
    BatchVerifier, Group, Parameters, Prover, Ristretto255, SecureRng, Transcript, Verifier,
    Witness,
};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

fn bench_batch_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_verification");

    for batch_size in [1, 2, 5, 10, 20, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("batch", batch_size),
            batch_size,
            |b, &size| {
                let mut rng = SecureRng::new();
                let params = Parameters::<Ristretto255>::new();

                let mut batch_verifier = BatchVerifier::new();
                for _ in 0..size {
                    let x = Ristretto255::random_scalar(&mut rng);
                    let witness = Witness::new(x);
                    let prover = Prover::new(params.clone(), witness);
                    let statement = prover.statement().clone();
                    let proof = prover.prove(&mut rng).unwrap();
                    batch_verifier
                        .add(params.clone(), statement, proof)
                        .unwrap();
                }

                b.iter(|| {
                    let results = black_box(batch_verifier.verify(&mut rng).unwrap());
                    assert_eq!(results.len(), size);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("individual", batch_size),
            batch_size,
            |b, &size| {
                let mut rng = SecureRng::new();
                let params = Parameters::<Ristretto255>::new();

                let mut proofs = Vec::new();
                for _ in 0..size {
                    let x = Ristretto255::random_scalar(&mut rng);
                    let witness = Witness::new(x);
                    let prover = Prover::new(params.clone(), witness);
                    let statement = prover.statement().clone();
                    let proof = prover.prove(&mut rng).unwrap();
                    let verifier = Verifier::new(params.clone(), statement);
                    proofs.push((verifier, proof));
                }

                b.iter(|| {
                    for (verifier, proof) in &proofs {
                        let _ = black_box(verifier.verify(proof));
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_batch_verification_with_transcript(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_verification_transcript");

    for batch_size in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("batch", batch_size),
            batch_size,
            |b, &size| {
                let mut rng = SecureRng::new();
                let params = Parameters::<Ristretto255>::new();

                let mut batch_verifier = BatchVerifier::new();
                for i in 0..size {
                    let x = Ristretto255::random_scalar(&mut rng);
                    let witness = Witness::new(x);
                    let prover = Prover::new(params.clone(), witness);
                    let statement = prover.statement().clone();

                    let context = format!("challenge-{}", i);
                    let mut transcript = Transcript::new();
                    transcript.append_context(context.as_bytes());
                    let proof = prover
                        .prove_with_transcript(&mut rng, &mut transcript)
                        .unwrap();

                    batch_verifier
                        .add_with_context(
                            params.clone(),
                            statement,
                            proof,
                            Some(context.into_bytes()),
                        )
                        .unwrap();
                }

                b.iter(|| {
                    let results = black_box(batch_verifier.verify(&mut rng).unwrap());
                    assert_eq!(results.len(), size);
                });
            },
        );
    }

    group.finish();
}

fn bench_batch_verification_mixed_validity(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_verification_mixed");

    let batch_size = 50;
    group.bench_function("mixed_valid_invalid", |b| {
        let mut rng = SecureRng::new();
        let params = Parameters::<Ristretto255>::new();

        let mut batch_verifier = BatchVerifier::new();
        for i in 0..batch_size {
            let x = Ristretto255::random_scalar(&mut rng);
            let witness = Witness::new(x);
            let prover = Prover::new(params.clone(), witness);
            let proof = prover.prove(&mut rng).unwrap();

            let statement = if i % 2 == 0 {
                prover.statement().clone()
            } else {
                let x2 = Ristretto255::random_scalar(&mut rng);
                let wrong_witness = Witness::new(x2);
                chaum_pedersen::Statement::from_witness(&params, &wrong_witness)
            };

            batch_verifier
                .add(params.clone(), statement, proof)
                .unwrap();
        }

        b.iter(|| {
            let results = black_box(batch_verifier.verify(&mut rng).unwrap());
            assert_eq!(results.len(), batch_size);
        });
    });

    group.finish();
}

fn bench_batch_add_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_add");

    group.bench_function("add_proof_to_batch", |b| {
        let mut rng = SecureRng::new();
        let params = Parameters::<Ristretto255>::new();

        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);
        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();
        let proof = prover.prove(&mut rng).unwrap();

        b.iter(|| {
            let mut batch_verifier = BatchVerifier::new();
            let _ = black_box(batch_verifier.add(params.clone(), statement.clone(), proof.clone()));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_batch_verification,
    bench_batch_verification_with_transcript,
    bench_batch_verification_mixed_validity,
    bench_batch_add_proof
);
criterion_main!(benches);
