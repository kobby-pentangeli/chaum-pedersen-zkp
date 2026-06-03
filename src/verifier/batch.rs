//! Batch verification for Chaum-Pedersen proofs.
//!
//! Folds the batch into one randomized check: each proof is weighted by a fresh random scalar, so
//! the batch accepts only if every proof is individually valid (Schwartz-Zippel). On failure it
//! falls back to verifying each proof to report which ones failed.

use rand_core::CryptoRngCore;

use crate::{Error, Parameters, Proof, Result, Ristretto255, Scalar, Statement, Transcript};

const MAX_BATCH_SIZE: usize = 1000;

struct BatchEntry {
    params: Parameters,
    statement: Statement,
    proof: Proof,
    transcript_context: Option<Vec<u8>>,
}

/// Accumulates proofs and verifies them in one randomized batch check.
///
/// Each proof gets a fresh random coefficient, giving the same soundness as individual
/// verification. Capacity is capped at 1000 proofs; split larger workloads across batches.
pub struct BatchVerifier {
    entries: Vec<BatchEntry>,
}

impl BatchVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Creates a batch verifier preallocated for `capacity` proofs (capped at the batch limit).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.min(MAX_BATCH_SIZE);
        Self {
            entries: Vec::with_capacity(cap),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        MAX_BATCH_SIZE.saturating_sub(self.entries.len())
    }

    pub fn add(&mut self, params: Parameters, statement: Statement, proof: Proof) -> Result<()> {
        self.add_with_context(params, statement, proof, None)
    }

    /// Adds a proof with custom transcript context to the batch.
    pub fn add_with_context(
        &mut self,
        params: Parameters,
        statement: Statement,
        proof: Proof,
        context: Option<Vec<u8>>,
    ) -> Result<()> {
        if self.entries.len() >= MAX_BATCH_SIZE {
            return Err(Error::BatchSizeExceeded {
                max: MAX_BATCH_SIZE,
                actual: self.entries.len().saturating_add(1),
            });
        }

        statement.validate()?;

        self.entries.push(BatchEntry {
            params,
            statement,
            proof,
            transcript_context: context,
        });

        Ok(())
    }

    /// Verifies the batch, returning a per-proof result; on batch failure it re-checks individually.
    pub fn verify<R: CryptoRngCore>(&self, rng: &mut R) -> Result<Vec<Result<()>>> {
        if self.entries.is_empty() {
            return Err(Error::BatchEmpty);
        }

        if self.entries.len() == 1 {
            return Ok(vec![self.verify_one(0)]);
        }

        self.verify_batch(rng)
    }

    fn verify_one(&self, index: usize) -> Result<()> {
        let entry = &self.entries[index];

        let mut transcript = Transcript::new();
        if let Some(context) = &entry.transcript_context {
            transcript.append_context(context);
        }

        transcript.append_parameters(
            &Ristretto255::element_to_bytes(entry.params.generator_g()),
            &Ristretto255::element_to_bytes(entry.params.generator_h()),
        );
        transcript.append_statement(
            &Ristretto255::element_to_bytes(entry.statement.y1()),
            &Ristretto255::element_to_bytes(entry.statement.y2()),
        );
        transcript.append_commitment(
            &Ristretto255::element_to_bytes(entry.proof.commitment().r1()),
            &Ristretto255::element_to_bytes(entry.proof.commitment().r2()),
        );

        let challenge = transcript.challenge_scalar();

        let g = entry.params.generator_g();
        let h = entry.params.generator_h();
        let y1 = entry.statement.y1();
        let y2 = entry.statement.y2();
        let r1 = entry.proof.commitment().r1();
        let r2 = entry.proof.commitment().r2();
        let s = entry.proof.response().s();

        let lhs1 = Ristretto255::scalar_mul(g, s);
        let y1_c = Ristretto255::scalar_mul(y1, &challenge);
        let rhs1 = Ristretto255::element_mul(r1, &y1_c);

        let lhs2 = Ristretto255::scalar_mul(h, s);
        let y2_c = Ristretto255::scalar_mul(y2, &challenge);
        let rhs2 = Ristretto255::element_mul(r2, &y2_c);

        if lhs1 != rhs1 || lhs2 != rhs2 {
            return Err(Error::VerificationFailed);
        }

        Ok(())
    }

    fn verify_batch<R: CryptoRngCore>(&self, rng: &mut R) -> Result<Vec<Result<()>>> {
        let n = self.entries.len();

        let mut coefficients = Vec::with_capacity(n);
        let mut challenges = Vec::with_capacity(n);

        for entry in &self.entries {
            coefficients.push(Ristretto255::random_scalar(rng));

            let mut transcript = Transcript::new();
            if let Some(context) = &entry.transcript_context {
                transcript.append_context(context);
            }
            transcript.append_parameters(
                &Ristretto255::element_to_bytes(entry.params.generator_g()),
                &Ristretto255::element_to_bytes(entry.params.generator_h()),
            );
            transcript.append_statement(
                &Ristretto255::element_to_bytes(entry.statement.y1()),
                &Ristretto255::element_to_bytes(entry.statement.y2()),
            );
            transcript.append_commitment(
                &Ristretto255::element_to_bytes(entry.proof.commitment().r1()),
                &Ristretto255::element_to_bytes(entry.proof.commitment().r2()),
            );

            challenges.push(transcript.challenge_scalar());
        }

        let batch_valid = self.verify_batch_equations(&coefficients, &challenges);

        if batch_valid {
            Ok((0..n).map(|_| Ok(())).collect())
        } else {
            Ok(self.verify_individually())
        }
    }

    fn verify_batch_equations(&self, coefficients: &[Scalar], challenges: &[Scalar]) -> bool {
        let n = self.entries.len();

        let mut lhs1 = Ristretto255::identity();
        let mut rhs1 = Ristretto255::identity();
        let mut lhs2 = Ristretto255::identity();
        let mut rhs2 = Ristretto255::identity();

        for i in 0..n {
            let entry = &self.entries[i];
            let alpha = &coefficients[i];
            let challenge = &challenges[i];

            let g = entry.params.generator_g();
            let h = entry.params.generator_h();
            let y1 = entry.statement.y1();
            let y2 = entry.statement.y2();
            let r1 = entry.proof.commitment().r1();
            let r2 = entry.proof.commitment().r2();
            let s = entry.proof.response().s();

            let alpha_s = Ristretto255::scalar_mul_scalar(alpha, s);

            let g_alpha_s = Ristretto255::scalar_mul(g, &alpha_s);
            lhs1 = Ristretto255::element_mul(&lhs1, &g_alpha_s);

            let r1_alpha = Ristretto255::scalar_mul(r1, alpha);
            let y1_c = Ristretto255::scalar_mul(y1, challenge);
            let term1 = Ristretto255::element_mul(&r1_alpha, &y1_c);
            rhs1 = Ristretto255::element_mul(&rhs1, &term1);

            let h_alpha_s = Ristretto255::scalar_mul(h, &alpha_s);
            lhs2 = Ristretto255::element_mul(&lhs2, &h_alpha_s);

            let r2_alpha = Ristretto255::scalar_mul(r2, alpha);
            let y2_c = Ristretto255::scalar_mul(y2, challenge);
            let term2 = Ristretto255::element_mul(&r2_alpha, &y2_c);
            rhs2 = Ristretto255::element_mul(&rhs2, &term2);
        }

        lhs1 == rhs1 && lhs2 == rhs2
    }

    fn verify_individually(&self) -> Vec<Result<()>> {
        (0..self.entries.len())
            .map(|i| self.verify_one(i))
            .collect()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Prover, SecureRng, Witness};

    #[test]
    fn empty_batch_fails() {
        let batch = BatchVerifier::new();
        let mut rng = SecureRng::new();
        assert!(batch.verify(&mut rng).is_err());
    }

    #[test]
    fn single_valid_proof() {
        let mut rng = SecureRng::new();
        let params = Parameters::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);
        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();
        let proof = prover.prove(&mut rng).unwrap();

        let mut batch = BatchVerifier::new();
        batch.add(params, statement, proof).unwrap();

        let results = batch.verify(&mut rng).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
    }

    #[test]
    fn single_invalid_proof() {
        let mut rng = SecureRng::new();
        let params = Parameters::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);
        let prover = Prover::new(params.clone(), witness);
        let proof = prover.prove(&mut rng).unwrap();

        let x2 = Ristretto255::random_scalar(&mut rng);
        let wrong_witness = Witness::new(x2);
        let wrong_statement = Statement::from_witness(&params, &wrong_witness);

        let mut batch = BatchVerifier::new();
        batch.add(params, wrong_statement, proof).unwrap();

        let results = batch.verify(&mut rng).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }

    #[test]
    fn multiple_valid_proofs() {
        let mut rng = SecureRng::new();
        let params = Parameters::new();
        let mut batch = BatchVerifier::new();

        for _ in 0..10 {
            let x = Ristretto255::random_scalar(&mut rng);
            let witness = Witness::new(x);
            let prover = Prover::new(params.clone(), witness);
            let statement = prover.statement().clone();
            let proof = prover.prove(&mut rng).unwrap();
            batch.add(params.clone(), statement, proof).unwrap();
        }

        let results = batch.verify(&mut rng).unwrap();
        assert_eq!(results.len(), 10);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[test]
    fn mixed_valid_invalid_proofs() {
        let mut rng = SecureRng::new();
        let params = Parameters::new();
        let mut batch = BatchVerifier::new();

        for i in 0..10 {
            let x = Ristretto255::random_scalar(&mut rng);
            let witness = Witness::new(x);
            let prover = Prover::new(params.clone(), witness);
            let proof = prover.prove(&mut rng).unwrap();

            let statement = if i % 2 == 0 {
                prover.statement().clone()
            } else {
                let x2 = Ristretto255::random_scalar(&mut rng);
                let wrong_witness = Witness::new(x2);
                Statement::from_witness(&params, &wrong_witness)
            };

            batch.add(params.clone(), statement, proof).unwrap();
        }

        let results = batch.verify(&mut rng).unwrap();
        assert_eq!(results.len(), 10);

        for (i, result) in results.iter().enumerate() {
            if i % 2 == 0 {
                assert!(result.is_ok(), "Proof {i} should be valid");
            } else {
                assert!(result.is_err(), "Proof {i} should be invalid");
            }
        }
    }

    #[test]
    fn batch_with_transcript_context() {
        let mut rng = SecureRng::new();
        let params = Parameters::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);

        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();

        let mut transcript = Transcript::new();
        transcript.append_context(b"challenge-12345");
        let proof = prover
            .prove_with_transcript(&mut rng, &mut transcript)
            .unwrap();

        let mut batch = BatchVerifier::new();
        batch
            .add_with_context(params, statement, proof, Some(b"challenge-12345".to_vec()))
            .unwrap();

        let results = batch.verify(&mut rng).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
    }

    #[test]
    fn batch_size_limit() {
        let mut batch = BatchVerifier::new();
        let mut rng = SecureRng::new();
        let params = Parameters::new();

        for _ in 0..MAX_BATCH_SIZE {
            let x = Ristretto255::random_scalar(&mut rng);
            let witness = Witness::new(x);
            let prover = Prover::new(params.clone(), witness);
            let statement = prover.statement().clone();
            let proof = prover.prove(&mut rng).unwrap();
            assert!(batch.add(params.clone(), statement, proof).is_ok());
        }

        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);
        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();
        let proof = prover.prove(&mut rng).unwrap();
        assert!(batch.add(params, statement, proof).is_err());
    }

    #[test]
    fn batch_capacity_tracking() {
        let batch = BatchVerifier::new();
        assert_eq!(batch.len(), 0);
        assert!(batch.is_empty());
        assert_eq!(batch.remaining_capacity(), MAX_BATCH_SIZE);
    }

    #[test]
    fn batch_clear() {
        let mut rng = SecureRng::new();
        let params = Parameters::new();
        let mut batch = BatchVerifier::new();

        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x);
        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();
        let proof = prover.prove(&mut rng).unwrap();
        batch.add(params, statement, proof).unwrap();

        assert!(!batch.is_empty());
        batch.clear();
        assert!(batch.is_empty());
    }
}
