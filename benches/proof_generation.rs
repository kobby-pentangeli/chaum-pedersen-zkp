use std::hint::black_box;

use chaum_pedersen::{
    Element, OsRng, Parameters, Prover, Scalar, Statement, Transcript, Verifier, Witness,
};
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_ristretto_proof_generation(c: &mut Criterion) {
    let params = Parameters::new();
    let mut rng = OsRng;
    let x = Scalar::random(&mut rng);
    let witness = Witness::new(x).unwrap();

    c.bench_function("ristretto_proof_generation", |b| {
        b.iter(|| {
            let mut transcript = Transcript::new();
            Prover::new(params.clone(), witness.clone())
                .prove_with_transcript(black_box(&mut rng), black_box(&mut transcript))
                .unwrap()
        })
    });
}

fn bench_ristretto_proof_verification(c: &mut Criterion) {
    let params = Parameters::new();
    let mut rng = OsRng;
    let x = Scalar::random(&mut rng);
    let witness = Witness::new(x).unwrap();
    let statement = Statement::from_witness(&params, &witness);

    let mut transcript = Transcript::new();
    let proof = Prover::new(params.clone(), witness)
        .prove_with_transcript(&mut rng, &mut transcript)
        .unwrap();

    c.bench_function("ristretto_proof_verification", |b| {
        b.iter(|| {
            let mut verify_transcript = Transcript::new();
            let verifier = Verifier::new(params.clone(), statement.clone());
            verifier
                .verify_with_transcript(black_box(&proof), black_box(&mut verify_transcript))
                .unwrap()
        })
    });
}

fn bench_statement_serialization(c: &mut Criterion) {
    let params = Parameters::new();
    let mut rng = OsRng;
    let x = Scalar::random(&mut rng);
    let witness = Witness::new(x).unwrap();
    let statement = Statement::from_witness(&params, &witness);

    c.bench_function("statement_serialization", |b| {
        b.iter(|| {
            let y1_bytes = black_box(statement.y1()).to_bytes();
            let y2_bytes = black_box(statement.y2()).to_bytes();
            (y1_bytes, y2_bytes)
        })
    });
}

fn bench_statement_deserialization(c: &mut Criterion) {
    let params = Parameters::new();
    let mut rng = OsRng;
    let x = Scalar::random(&mut rng);
    let witness = Witness::new(x).unwrap();
    let statement = Statement::from_witness(&params, &witness);

    let y1_bytes = statement.y1().to_bytes();
    let y2_bytes = statement.y2().to_bytes();

    c.bench_function("statement_deserialization", |b| {
        b.iter(|| {
            let y1 = Element::from_bytes(black_box(&y1_bytes)).unwrap();
            let y2 = Element::from_bytes(black_box(&y2_bytes)).unwrap();
            Statement::new(y1, y2).unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_ristretto_proof_generation,
    bench_ristretto_proof_verification,
    bench_statement_serialization,
    bench_statement_deserialization
);
criterion_main!(benches);
