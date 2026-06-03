//! Prover (client) implementation for the Chaum-Pedersen protocol.

use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Commitment, Parameters, Proof, Response, Result, Ristretto255, Scalar, Statement, Transcript,
    Witness,
};

/// Prover for the Chaum-Pedersen zero-knowledge protocol.
///
/// Generates proofs of knowledge of a discrete logarithm `x` such that `y1 = g^x` and `y2 = h^x`
/// without revealing `x`.
///
/// # Security
///
/// - Use [`SecureRng`](crate::SecureRng) for randomness.
/// - Bind proofs to a context via the transcript to prevent replay.
/// - Never reuse a witness across protocol instances.
pub struct Prover {
    params: Parameters,
    witness: Witness,
    statement: Statement,
}

impl Prover {
    /// Creates a prover, computing the statement from the witness as `y1 = g^x`, `y2 = h^x`.
    pub fn new(params: Parameters, witness: Witness) -> Self {
        let statement = Statement::from_witness(&params, &witness);
        Self {
            params,
            witness,
            statement,
        }
    }

    /// Creates a prover from a precomputed statement; the caller must ensure it matches the witness.
    pub fn with_statement(params: Parameters, witness: Witness, statement: Statement) -> Self {
        Self {
            params,
            witness,
            statement,
        }
    }

    pub fn statement(&self) -> &Statement {
        &self.statement
    }

    /// Generates a non-interactive Fiat-Shamir proof. This is
    /// the recommended entry point.
    pub fn prove<R: CryptoRngCore>(&self, rng: &mut R) -> Result<Proof> {
        let mut transcript = Transcript::new();
        self.prove_with_transcript(rng, &mut transcript)
    }

    /// Generates a proof over a caller-supplied transcript, enabling extra context binding.
    pub fn prove_with_transcript<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> Result<Proof> {
        let (commitment, nonce) = self.commit(rng);

        transcript.append_parameters(
            &Ristretto255::element_to_bytes(self.params.generator_g()),
            &Ristretto255::element_to_bytes(self.params.generator_h()),
        );
        transcript.append_statement(
            &Ristretto255::element_to_bytes(self.statement.y1()),
            &Ristretto255::element_to_bytes(self.statement.y2()),
        );
        transcript.append_commitment(
            &Ristretto255::element_to_bytes(commitment.r1()),
            &Ristretto255::element_to_bytes(commitment.r2()),
        );

        let challenge = transcript.challenge_scalar();
        let response = self.respond(&nonce, &challenge);

        Ok(Proof::new(commitment, response))
    }

    /// Interactive protocol, message 1: returns the commitment and the secret nonce to retain.
    pub fn commit<R: CryptoRngCore>(&self, rng: &mut R) -> (Commitment, Nonce) {
        let k = Ristretto255::random_scalar(rng);
        let r1 = Ristretto255::scalar_mul(self.params.generator_g(), &k);
        let r2 = Ristretto255::scalar_mul(self.params.generator_h(), &k);

        (Commitment::new(r1, r2), Nonce::new(k))
    }

    /// Interactive protocol, message 3: combines the nonce and challenge into the response.
    pub fn respond(&self, nonce: &Nonce, challenge: &Scalar) -> Response {
        let cx = Ristretto255::scalar_mul_scalar(challenge, self.witness.secret());
        let s = Ristretto255::scalar_add(nonce.k(), &cx);

        Response::new(s)
    }
}

/// Secret nonce from the commitment phase; zeroized on drop.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Nonce {
    k: Scalar,
}

impl Nonce {
    pub fn new(k: Scalar) -> Self {
        Self { k }
    }

    pub fn k(&self) -> &Scalar {
        &self.k
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecureRng;

    #[test]
    fn prover_creation() {
        let mut rng = SecureRng::new();
        let params = Parameters::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);

        let prover = Prover::new(params, witness);
        assert!(prover.statement().y1() != &Ristretto255::identity());
    }

    #[test]
    fn prove_generates_valid_proof() {
        let mut rng = SecureRng::new();
        let params = Parameters::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);

        let prover = Prover::new(params, witness);
        let proof = prover.prove(&mut rng).unwrap();

        assert_eq!(proof.version(), 1);
    }

    #[test]
    fn interactive_protocol() {
        let mut rng = SecureRng::new();
        let params = Parameters::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);

        let prover = Prover::new(params, witness);
        let (_commitment, nonce) = prover.commit(&mut rng);
        let challenge = Ristretto255::random_scalar(&mut rng);
        let response = prover.respond(&nonce, &challenge);

        assert!(!Ristretto255::scalar_is_zero(response.s()));
    }
}
