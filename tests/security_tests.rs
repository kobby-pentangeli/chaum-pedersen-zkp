use chaum_pedersen::{
    Parameters, Proof, Prover, Ristretto255, SecureRng, Statement, Transcript, Verifier, Witness,
};

#[test]
fn prevent_replay_attack_with_different_contexts() {
    let params = Parameters::new();
    let mut rng = SecureRng::new();

    let x = Ristretto255::random_scalar(&mut rng);
    let witness = Witness::new(x);
    let statement = Statement::from_witness(&params, &witness);

    let mut transcript1 = Transcript::new();
    transcript1.append_context(b"session-1");
    let proof1 = Prover::new(params.clone(), witness.clone())
        .prove_with_transcript(&mut rng, &mut transcript1)
        .expect("Proof generation should succeed");

    let mut verify_transcript1 = Transcript::new();
    verify_transcript1.append_context(b"session-1");
    let verifier1 = Verifier::new(params.clone(), statement.clone());
    assert!(
        verifier1
            .verify_with_transcript(&proof1, &mut verify_transcript1)
            .is_ok(),
        "Proof should verify with matching context"
    );

    let mut verify_transcript2 = Transcript::new();
    verify_transcript2.append_context(b"session-2");
    let verifier2 = Verifier::new(params, statement);
    assert!(
        verifier2
            .verify_with_transcript(&proof1, &mut verify_transcript2)
            .is_err(),
        "Proof should fail verification with different context (replay protection)"
    );
}

#[test]
fn reject_invalid_proof_corrupted_commitment() {
    let params = Parameters::new();
    let mut rng = SecureRng::new();

    let x = Ristretto255::random_scalar(&mut rng);
    let witness = Witness::new(x);
    let statement = Statement::from_witness(&params, &witness);

    let mut transcript = Transcript::new();
    let proof = Prover::new(params.clone(), witness)
        .prove_with_transcript(&mut rng, &mut transcript)
        .expect("Proof generation should succeed");

    let mut proof_bytes = proof.to_bytes().expect("Serialization should succeed");

    let commitment_start = 1;
    if proof_bytes.len() > commitment_start + 10 {
        proof_bytes[commitment_start + 5] ^= 0xFF;
    }

    if let Ok(corrupted_proof) = Proof::from_bytes(&proof_bytes) {
        let mut verify_transcript = Transcript::new();
        let verifier = Verifier::new(params, statement);
        assert!(
            verifier
                .verify_with_transcript(&corrupted_proof, &mut verify_transcript)
                .is_err(),
            "Corrupted proof should fail verification"
        );
    }
}

#[test]
fn reject_invalid_proof_corrupted_response() {
    let params = Parameters::new();
    let mut rng = SecureRng::new();

    let x = Ristretto255::random_scalar(&mut rng);
    let witness = Witness::new(x);
    let statement = Statement::from_witness(&params, &witness);

    let mut transcript = Transcript::new();
    let proof = Prover::new(params.clone(), witness)
        .prove_with_transcript(&mut rng, &mut transcript)
        .expect("Proof generation should succeed");

    let mut proof_bytes = proof.to_bytes().expect("Serialization should succeed");

    let len = proof_bytes.len();
    if len > 100 {
        proof_bytes[len - 10] ^= 0xFF;
    }

    if let Ok(corrupted_proof) = Proof::from_bytes(&proof_bytes) {
        let mut verify_transcript = Transcript::new();
        let verifier = Verifier::new(params, statement);
        assert!(
            verifier
                .verify_with_transcript(&corrupted_proof, &mut verify_transcript)
                .is_err(),
            "Proof with corrupted response should fail verification"
        );
    }
}

#[test]
fn proof_cannot_be_used_for_different_statement() {
    let params = Parameters::new();
    let mut rng = SecureRng::new();

    let x1 = Ristretto255::random_scalar(&mut rng);
    let witness1 = Witness::new(x1);
    let _statement1 = Statement::from_witness(&params, &witness1);

    let x2 = Ristretto255::random_scalar(&mut rng);
    let witness2 = Witness::new(x2);
    let statement2 = Statement::from_witness(&params, &witness2);

    let mut transcript = Transcript::new();
    let proof = Prover::new(params.clone(), witness1)
        .prove_with_transcript(&mut rng, &mut transcript)
        .expect("Proof generation should succeed");

    let mut verify_transcript = Transcript::new();
    let verifier = Verifier::new(params, statement2);
    assert!(
        verifier
            .verify_with_transcript(&proof, &mut verify_transcript)
            .is_err(),
        "Proof should not verify for a different statement"
    );
}

#[test]
fn detect_identity_element() {
    let identity = Ristretto255::identity();
    let statement = Statement::new(identity.clone(), identity.clone());

    assert!(
        Ristretto255::is_identity(&identity),
        "Identity element should be detectable"
    );

    assert!(
        statement.validate().is_ok(),
        "Statement validation allows identity (note: this is a known limitation)"
    );
}

#[test]
fn proof_deserialization_rejects_malformed_data() {
    let test_cases = vec![vec![], vec![0x00], vec![0xFF; 10], vec![0x01; 1000]];

    for malformed_data in test_cases {
        let result = Proof::from_bytes(&malformed_data);
        assert!(
            result.is_err(),
            "Malformed proof data should be rejected: {:?}",
            malformed_data
        );
    }
}

#[test]
fn multiple_proofs_for_same_witness_are_different() {
    let params = Parameters::new();
    let mut rng = SecureRng::new();

    let x = Ristretto255::random_scalar(&mut rng);
    let witness = Witness::new(x);
    let statement = Statement::from_witness(&params, &witness);

    let mut transcript1 = Transcript::new();
    let proof1 = Prover::new(params.clone(), witness.clone())
        .prove_with_transcript(&mut rng, &mut transcript1)
        .expect("Proof generation should succeed");

    let mut transcript2 = Transcript::new();
    let proof2 = Prover::new(params.clone(), witness)
        .prove_with_transcript(&mut rng, &mut transcript2)
        .expect("Proof generation should succeed");

    let proof1_bytes = proof1.to_bytes().expect("Serialization should succeed");
    let proof2_bytes = proof2.to_bytes().expect("Serialization should succeed");

    assert_ne!(
        proof1_bytes, proof2_bytes,
        "Multiple proofs for same witness should be different (randomized)"
    );

    let mut verify_transcript1 = Transcript::new();
    let verifier1 = Verifier::new(params.clone(), statement.clone());
    assert!(
        verifier1
            .verify_with_transcript(&proof1, &mut verify_transcript1)
            .is_ok(),
        "First proof should verify"
    );

    let mut verify_transcript2 = Transcript::new();
    let verifier2 = Verifier::new(params, statement);
    assert!(
        verifier2
            .verify_with_transcript(&proof2, &mut verify_transcript2)
            .is_ok(),
        "Second proof should verify"
    );
}

#[test]
fn proof_size_is_reasonable() {
    let params = Parameters::new();
    let mut rng = SecureRng::new();

    let x = Ristretto255::random_scalar(&mut rng);
    let witness = Witness::new(x);

    let mut transcript = Transcript::new();
    let proof = Prover::new(params, witness)
        .prove_with_transcript(&mut rng, &mut transcript)
        .expect("Proof generation should succeed");

    let proof_bytes = proof.to_bytes().expect("Serialization should succeed");

    assert!(
        proof_bytes.len() < 1024,
        "Proof size should be less than 1KB, got {} bytes",
        proof_bytes.len()
    );

    assert!(
        proof_bytes.len() > 32,
        "Proof size should be more than 32 bytes, got {} bytes",
        proof_bytes.len()
    );
}
