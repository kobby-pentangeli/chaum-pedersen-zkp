use chaum_pedersen::{
    Group, Parameters, Proof, Prover, Ristretto255, SecureRng, Statement, Transcript, Verifier,
    Witness,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn proof_verifies_for_any_valid_witness(_seed in any::<u64>()) {
        let params = Parameters::<Ristretto255>::new();
        let mut rng = SecureRng::new();

        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);
        let statement = Statement::from_witness(&params, &witness);

        let mut transcript = Transcript::new();
        let proof = Prover::new(params.clone(), witness)
            .prove_with_transcript(&mut rng, &mut transcript)
            .expect("Proof generation should succeed");

        let mut verify_transcript = Transcript::new();
        let verifier = Verifier::new(params, statement);
        let result = verifier.verify_with_transcript(&proof, &mut verify_transcript);

        prop_assert!(result.is_ok(), "Valid proof should verify successfully");
    }

    #[test]
    fn proof_fails_for_wrong_statement(_seed1 in any::<u64>(), _seed2 in any::<u64>()) {
        let params = Parameters::<Ristretto255>::new();
        let mut rng = SecureRng::new();

        let x1 = Ristretto255::random_scalar(&mut rng);
        let witness1 = Witness::new(x1);
        let statement1 = Statement::from_witness(&params, &witness1);

        let x2 = Ristretto255::random_scalar(&mut rng);
        let witness2 = Witness::new(x2);
        let statement2 = Statement::from_witness(&params, &witness2);

        if statement1.y1() == statement2.y1() && statement1.y2() == statement2.y2() {
            return Ok(());
        }

        let mut transcript = Transcript::new();
        let proof = Prover::new(params.clone(), witness1)
            .prove_with_transcript(&mut rng, &mut transcript)
            .expect("Proof generation should succeed");

        let mut verify_transcript = Transcript::new();
        let verifier = Verifier::new(params, statement2);
        let result = verifier.verify_with_transcript(&proof, &mut verify_transcript);

        prop_assert!(result.is_err(), "Proof with wrong statement should fail verification");
    }

    #[test]
    fn proof_serialization_roundtrip(_seed in any::<u64>()) {
        let params = Parameters::<Ristretto255>::new();
        let mut rng = SecureRng::new();

        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);
        let statement = Statement::from_witness(&params, &witness);

        let mut transcript = Transcript::new();
        let proof = Prover::new(params.clone(), witness)
            .prove_with_transcript(&mut rng, &mut transcript)
            .expect("Proof generation should succeed");

        let serialized = proof.to_bytes().expect("Serialization should succeed");
        let deserialized = Proof::<Ristretto255>::from_bytes(&serialized)
            .expect("Deserialization should succeed");

        let mut verify_transcript = Transcript::new();
        let verifier = Verifier::new(params, statement);
        let result = verifier.verify_with_transcript(&deserialized, &mut verify_transcript);

        prop_assert!(result.is_ok(), "Deserialized proof should verify successfully");
    }

    #[test]
    fn statement_serialization_preserves_validity(_seed in any::<u64>()) {
        let params = Parameters::<Ristretto255>::new();
        let mut rng = SecureRng::new();

        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);
        let statement = Statement::from_witness(&params, &witness);

        let y1_bytes = Ristretto255::element_to_bytes(statement.y1());
        let y2_bytes = Ristretto255::element_to_bytes(statement.y2());

        let y1_reconstructed = Ristretto255::element_from_bytes(&y1_bytes)
            .expect("y1 deserialization should succeed");
        let y2_reconstructed = Ristretto255::element_from_bytes(&y2_bytes)
            .expect("y2 deserialization should succeed");

        let statement_reconstructed: Statement<Ristretto255> =
            Statement::new(y1_reconstructed, y2_reconstructed);

        prop_assert!(
            statement_reconstructed.validate().is_ok(),
            "Reconstructed statement should be valid"
        );
    }
}
