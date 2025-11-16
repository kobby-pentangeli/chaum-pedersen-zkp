use super::{Parameters, Proof, Statement, Transcript};
use crate::{Group, Result};

/// Verifier for the Chaum-Pedersen zero-knowledge protocol.
///
/// Validates proofs of discrete logarithm equality.
pub struct Verifier<G: Group> {
    params: Parameters<G>,
    statement: Statement<G>,
}

impl<G: Group> Verifier<G> {
    /// Creates a new verifier with the given parameters and statement.
    pub fn new(params: Parameters<G>, statement: Statement<G>) -> Self {
        Self { params, statement }
    }

    /// Verifies a non-interactive zero-knowledge proof.
    ///
    /// Returns `Ok(())` if the proof is valid, `Err` otherwise.
    pub fn verify(&self, proof: &Proof<G>) -> Result<()> {
        let mut transcript = Transcript::new();
        self.verify_with_transcript(proof, &mut transcript)
    }

    /// Verifies a proof using a custom transcript.
    ///
    /// The transcript must match the one used during proof generation.
    pub fn verify_with_transcript(
        &self,
        proof: &Proof<G>,
        transcript: &mut Transcript,
    ) -> Result<()> {
        self.statement.validate()?;

        transcript.append_group_name(G::name());
        transcript.append_parameters(
            &G::element_to_bytes(self.params.generator_g()),
            &G::element_to_bytes(self.params.generator_h()),
        );
        transcript.append_statement(
            &G::element_to_bytes(self.statement.y1()),
            &G::element_to_bytes(self.statement.y2()),
        );
        transcript.append_commitment(
            &G::element_to_bytes(proof.commitment().r1()),
            &G::element_to_bytes(proof.commitment().r2()),
        );

        let challenge = transcript.challenge_scalar::<G>();

        self.verify_response(&challenge, proof)
    }

    /// Interactive protocol: verifies the response (fourth message).
    ///
    /// Checks that `g^s = r1 * y1^c` and `h^s = r2 * y2^c`.
    pub fn verify_response(&self, challenge: &G::Scalar, proof: &Proof<G>) -> Result<()> {
        let g = self.params.generator_g();
        let h = self.params.generator_h();
        let y1 = self.statement.y1();
        let y2 = self.statement.y2();
        let r1 = proof.commitment().r1();
        let r2 = proof.commitment().r2();
        let s = proof.response().s();

        let lhs1 = G::scalar_mul(g, s);
        let y1_c = G::scalar_mul(y1, challenge);
        let rhs1 = G::element_mul(r1, &y1_c);

        let lhs2 = G::scalar_mul(h, s);
        let y2_c = G::scalar_mul(y2, challenge);
        let rhs2 = G::element_mul(r2, &y2_c);

        let check1 = lhs1 == rhs1;
        let check2 = lhs2 == rhs2;

        if !check1 || !check2 {
            return Err(crate::Error::InvalidParams(
                "Proof verification failed".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Prover, Ristretto255, SecureRng, Witness};

    #[test]
    fn verifier_accepts_valid_proof() {
        let mut rng = SecureRng::new();
        let params = Parameters::<Ristretto255>::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);

        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();
        let proof = prover.prove(&mut rng).unwrap();

        let verifier = Verifier::new(params, statement);
        assert!(verifier.verify(&proof).is_ok());
    }

    #[test]
    fn verifier_rejects_invalid_statement() {
        let mut rng = SecureRng::new();
        let params = Parameters::<Ristretto255>::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);

        let prover = Prover::new(params.clone(), witness);
        let proof = prover.prove(&mut rng).unwrap();

        let x2 = Ristretto255::random_scalar(&mut rng);
        let wrong_witness = Witness::new(x2);
        let wrong_statement = Statement::from_witness(&params, &wrong_witness);

        let verifier = Verifier::new(params, wrong_statement);
        assert!(verifier.verify(&proof).is_err());
    }

    #[test]
    fn interactive_verification() {
        let mut rng = SecureRng::new();
        let params = Parameters::<Ristretto255>::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);

        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();

        let (commitment, nonce) = prover.commit(&mut rng);
        let challenge = Ristretto255::random_scalar(&mut rng);
        let response = prover.respond(&nonce, &challenge);
        let proof = Proof::new(commitment, response);

        let verifier = Verifier::new(params, statement);
        assert!(verifier.verify_response(&challenge, &proof).is_ok());
    }
}
