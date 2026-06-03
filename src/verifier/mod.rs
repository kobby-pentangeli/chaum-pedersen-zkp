//! Verifier (server) implementation:
//! proof validation plus server state, config, and gRPC.

use crate::{Element, Error, Parameters, Proof, Result, Scalar, Statement, Transcript};

pub mod batch;

#[cfg(feature = "server")]
pub mod config;

#[cfg(feature = "server")]
pub mod service;

#[cfg(feature = "server")]
pub mod state;

pub use batch::BatchVerifier;
#[cfg(feature = "server")]
pub use config::{RateLimiter, ServerConfig};
#[cfg(feature = "server")]
pub use service::AuthServiceImpl;
#[cfg(feature = "server")]
pub use state::ServerState;

/// Verifier for the Chaum-Pedersen zero-knowledge protocol.
///
/// Validates proofs of discrete-log equality without learning `x`.
///
/// # Security
///
/// - Verification rejects identity statement/commitment elements and a zero
///   challenge; invalid inputs are rejected, never accepted.
/// - Use the same transcript context as the prover; a mismatch rejects the proof (anti-replay).
pub struct Verifier {
    params: Parameters,
    statement: Statement,
}

impl Verifier {
    pub fn new(params: Parameters, statement: Statement) -> Self {
        Self { params, statement }
    }

    /// Verifies a non-interactive proof; `Ok(())` if valid.
    pub fn verify(&self, proof: &Proof) -> Result<()> {
        let mut transcript = Transcript::new();
        self.verify_with_transcript(proof, &mut transcript)
    }

    /// Verifies a proof against a transcript that must match the prover's; the context binding
    /// prevents replay.
    pub fn verify_with_transcript(&self, proof: &Proof, transcript: &mut Transcript) -> Result<()> {
        transcript.append_parameters(
            &self.params.generator_g().to_bytes(),
            &self.params.generator_h().to_bytes(),
        );
        transcript.append_statement(
            &self.statement.y1().to_bytes(),
            &self.statement.y2().to_bytes(),
        );
        transcript.append_commitment(
            &proof.commitment().r1().to_bytes(),
            &proof.commitment().r2().to_bytes(),
        );

        let challenge = transcript.challenge_scalar();

        self.verify_response(&challenge, proof)
    }

    /// Interactive protocol, message 4: checks `g^s = r1·y1^c` and `h^s = r2·y2^c`.
    pub fn verify_response(&self, challenge: &Scalar, proof: &Proof) -> Result<()> {
        self.statement.validate()?;
        proof.commitment().validate()?;

        if challenge.is_zero() {
            return Err(Error::VerificationFailed);
        }

        let g = self.params.generator_g();
        let h = self.params.generator_h();
        let y1 = self.statement.y1();
        let y2 = self.statement.y2();
        let r1 = proof.commitment().r1();
        let r2 = proof.commitment().r2();
        let s = proof.response().s();

        let neg_c = -challenge;
        let lhs1 =
            Element::vartime_multiscalar_mul(&[s.clone(), neg_c.clone()], &[g.clone(), y1.clone()]);
        let lhs2 = Element::vartime_multiscalar_mul(&[s.clone(), neg_c], &[h.clone(), y2.clone()]);

        if &lhs1 != r1 || &lhs2 != r2 {
            return Err(Error::VerificationFailed);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OsRng, Prover, Witness};

    #[test]
    fn verifier_accepts_valid_proof() {
        let mut rng = OsRng;
        let params = Parameters::new();
        let x = Scalar::random(&mut rng);
        let witness = Witness::new(x).unwrap();

        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();
        let proof = prover.prove(&mut rng).unwrap();

        let verifier = Verifier::new(params, statement);
        assert!(verifier.verify(&proof).is_ok());
    }

    #[test]
    fn verifier_rejects_invalid_statement() {
        let mut rng = OsRng;
        let params = Parameters::new();
        let x = Scalar::random(&mut rng);
        let witness = Witness::new(x).unwrap();

        let prover = Prover::new(params.clone(), witness);
        let proof = prover.prove(&mut rng).unwrap();

        let x2 = Scalar::random(&mut rng);
        let wrong_witness = Witness::new(x2).unwrap();
        let wrong_statement = Statement::from_witness(&params, &wrong_witness);

        let verifier = Verifier::new(params, wrong_statement);
        assert!(verifier.verify(&proof).is_err());
    }

    #[test]
    fn interactive_verification() {
        let mut rng = OsRng;
        let params = Parameters::new();
        let x = Scalar::random(&mut rng);
        let witness = Witness::new(x).unwrap();

        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();

        let (commitment, nonce) = prover.commit(&mut rng);
        let challenge = Scalar::random(&mut rng);
        let response = prover.respond(&nonce, &challenge);
        let proof = Proof::new(commitment, response);

        let verifier = Verifier::new(params, statement);
        assert!(verifier.verify_response(&challenge, &proof).is_ok());
    }
}
