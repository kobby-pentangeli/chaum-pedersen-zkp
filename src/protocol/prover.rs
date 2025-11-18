use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{Commitment, Parameters, Proof, Response, Statement, Transcript, Witness};
use crate::{Group, Result};

/// Prover for the Chaum-Pedersen zero-knowledge protocol.
///
/// Generates zero-knowledge proofs demonstrating knowledge of a discrete logarithm `x`
/// such that `y1 = g^x` and `y2 = h^x` without revealing `x`.
///
/// # Security
///
/// - Always use [`SecureRng`](crate::SecureRng) for randomness generation
/// - Bind proofs to specific contexts using transcript methods to prevent replay attacks
/// - Never reuse witness values across different protocol instances
/// - Ensure the witness is zeroized after use (automatic with [`Witness`])
pub struct Prover<G: Group> {
    params: Parameters<G>,
    witness: Witness<G>,
    statement: Statement<G>,
}

impl<G: Group> Prover<G> {
    /// Creates a new prover with the given parameters and witness.
    ///
    /// The statement is automatically computed from the witness as `y1 = g^x` and `y2 = h^x`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chaum_pedersen::{Prover, Parameters, Witness, Ristretto255, Group, SecureRng};
    ///
    /// let params = Parameters::<Ristretto255>::new();
    /// let mut rng = SecureRng::new();
    /// let x = Ristretto255::random_scalar(&mut rng);
    /// let witness = Witness::new(x);
    ///
    /// let prover = Prover::new(params, witness);
    /// ```
    pub fn new(params: Parameters<G>, witness: Witness<G>) -> Self {
        let statement = Statement::from_witness(&params, &witness);
        Self {
            params,
            witness,
            statement,
        }
    }

    /// Creates a prover from an existing statement and witness.
    ///
    /// # Security
    ///
    /// The caller must ensure the statement was correctly computed from the witness.
    pub fn with_statement(
        params: Parameters<G>,
        witness: Witness<G>,
        statement: Statement<G>,
    ) -> Self {
        Self {
            params,
            witness,
            statement,
        }
    }

    /// Returns the public statement.
    pub fn statement(&self) -> &Statement<G> {
        &self.statement
    }

    /// Generates a non-interactive zero-knowledge proof using Fiat-Shamir.
    ///
    /// This is the recommended method for most use cases.
    pub fn prove<R: CryptoRngCore>(&self, rng: &mut R) -> Result<Proof<G>> {
        let mut transcript = Transcript::new();
        self.prove_with_transcript(rng, &mut transcript)
    }

    /// Generates a proof using a custom transcript.
    ///
    /// Allows the caller to add additional context to the transcript.
    pub fn prove_with_transcript<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> Result<Proof<G>> {
        let (commitment, nonce) = self.commit(rng);

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
            &G::element_to_bytes(commitment.r1()),
            &G::element_to_bytes(commitment.r2()),
        );

        let challenge = transcript.challenge_scalar::<G>();
        let response = self.respond(&nonce, &challenge);

        Ok(Proof::new(commitment, response))
    }

    /// Interactive protocol: generates commitment (first message).
    ///
    /// Returns the commitment and the secret nonce (must be kept secret).
    pub fn commit<R: CryptoRngCore>(&self, rng: &mut R) -> (Commitment<G>, Nonce<G>) {
        let k = G::random_scalar(rng);
        let r1 = G::scalar_mul(self.params.generator_g(), &k);
        let r2 = G::scalar_mul(self.params.generator_h(), &k);

        (Commitment::new(r1, r2), Nonce::new(k))
    }

    /// Interactive protocol: generates response (third message).
    ///
    /// Takes the secret nonce and the challenge to produce the response.
    pub fn respond(&self, nonce: &Nonce<G>, challenge: &G::Scalar) -> Response<G> {
        let cx = G::scalar_mul_scalar(challenge, self.witness.secret());
        let s = G::scalar_add(nonce.k(), &cx);

        Response::new(s)
    }
}

/// Secret nonce used in the commitment phase.
///
/// Automatically zeroized when dropped.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Nonce<G: Group> {
    k: G::Scalar,
}

impl<G: Group> Nonce<G> {
    /// Creates a new nonce from a scalar.
    pub fn new(k: G::Scalar) -> Self {
        Self { k }
    }

    /// Returns a reference to the nonce scalar.
    pub fn k(&self) -> &G::Scalar {
        &self.k
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ristretto255, SecureRng};

    #[test]
    fn prover_creation() {
        let mut rng = SecureRng::new();
        let params = Parameters::<Ristretto255>::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);

        let prover = Prover::new(params, witness);
        assert!(prover.statement().y1() != &Ristretto255::identity());
    }

    #[test]
    fn prove_generates_valid_proof() {
        let mut rng = SecureRng::new();
        let params = Parameters::<Ristretto255>::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);

        let prover = Prover::new(params, witness);
        let proof = prover.prove(&mut rng).unwrap();

        assert_eq!(proof.version(), 1);
    }

    #[test]
    fn interactive_protocol() {
        let mut rng = SecureRng::new();
        let params = Parameters::<Ristretto255>::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);

        let prover = Prover::new(params, witness);
        let (_commitment, nonce) = prover.commit(&mut rng);
        let challenge = Ristretto255::random_scalar(&mut rng);
        let response = prover.respond(&nonce, &challenge);

        assert!(!Ristretto255::scalar_is_zero(response.s()));
    }
}
