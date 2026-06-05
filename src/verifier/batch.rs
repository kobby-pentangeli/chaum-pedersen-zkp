//! Batch verification for Chaum-Pedersen proofs.
//!
//! Folds every proof's two verification equations into a single variable-time multiscalar
//! multiplication, each equation weighted by a fresh random scalar, so the batch is the identity
//! iff every proof is individually valid (Schwartz-Zippel). On failure it falls back to verifying
//! each proof to report which ones failed.

use rand_core::CryptoRngCore;

use crate::{Element, Error, Parameters, Proof, Result, Scalar, Statement, Transcript};

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
        proof.commitment().validate()?;

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

    fn entry_challenge(entry: &BatchEntry) -> Scalar {
        let mut transcript = Transcript::new();
        if let Some(context) = &entry.transcript_context {
            transcript.append_context(context);
        }
        transcript.append_parameters(
            &entry.params.generator_g().to_bytes(),
            &entry.params.generator_h().to_bytes(),
        );
        transcript.append_statement(
            &entry.statement.y1().to_bytes(),
            &entry.statement.y2().to_bytes(),
        );
        transcript.append_commitment(
            &entry.proof.commitment().r1().to_bytes(),
            &entry.proof.commitment().r2().to_bytes(),
        );
        transcript.challenge_scalar()
    }

    fn verify_one(&self, index: usize) -> Result<()> {
        let entry = &self.entries[index];
        let challenge = Self::entry_challenge(entry);

        let g = entry.params.generator_g();
        let h = entry.params.generator_h();
        let y1 = entry.statement.y1();
        let y2 = entry.statement.y2();
        let r1 = entry.proof.commitment().r1();
        let r2 = entry.proof.commitment().r2();
        let s = entry.proof.response().s();

        let neg_c = -&challenge;
        let lhs1 =
            Element::vartime_multiscalar_mul(&[s.clone(), neg_c.clone()], &[g.clone(), y1.clone()]);
        let lhs2 = Element::vartime_multiscalar_mul(&[s.clone(), neg_c], &[h.clone(), y2.clone()]);

        if &lhs1 != r1 || &lhs2 != r2 {
            return Err(Error::VerificationFailed);
        }

        Ok(())
    }

    fn verify_batch<R: CryptoRngCore>(&self, rng: &mut R) -> Result<Vec<Result<()>>> {
        let weights = (0..self.entries.len())
            .map(|_| (Scalar::random(rng), Scalar::random(rng)))
            .collect::<Vec<(Scalar, Scalar)>>();
        let challenges = self
            .entries
            .iter()
            .map(Self::entry_challenge)
            .collect::<Vec<Scalar>>();

        if self.verify_batch_equation(&weights, &challenges) {
            Ok(self.entries.iter().map(|_| Ok(())).collect())
        } else {
            Ok(self.verify_individually())
        }
    }

    /// Folds every proof's two verification equations into one
    /// randomized multiscalar multiplication that is the identity iff each proof is
    /// individually valid.
    fn verify_batch_equation(&self, weights: &[(Scalar, Scalar)], challenges: &[Scalar]) -> bool {
        let per_proof = self.entries.iter().zip(weights).zip(challenges).flat_map(
            |((entry, (alpha, beta)), challenge)| {
                let y1 = entry.statement.y1();
                let y2 = entry.statement.y2();
                let r1 = entry.proof.commitment().r1();
                let r2 = entry.proof.commitment().r2();

                [
                    (-alpha, r1.clone()),
                    (-beta, r2.clone()),
                    (-(alpha * challenge), y1.clone()),
                    (-(beta * challenge), y2.clone()),
                ]
            },
        );

        let first = &self.entries[0].params;
        let shared = self.entries.iter().all(|e| {
            e.params.generator_g() == first.generator_g()
                && e.params.generator_h() == first.generator_h()
        });

        let generators: Vec<(Scalar, Element)> = if shared {
            let (sum_alpha_s, sum_beta_s) = self.entries.iter().zip(weights).fold(
                (Scalar::zero(), Scalar::zero()),
                |(sa, sb), (entry, (alpha, beta))| {
                    let s = entry.proof.response().s();
                    (sa + &(alpha * s), sb + &(beta * s))
                },
            );
            vec![
                (sum_alpha_s, first.generator_g().clone()),
                (sum_beta_s, first.generator_h().clone()),
            ]
        } else {
            self.entries
                .iter()
                .zip(weights)
                .flat_map(|(entry, (alpha, beta))| {
                    let s = entry.proof.response().s();
                    [
                        (alpha * s, entry.params.generator_g().clone()),
                        (beta * s, entry.params.generator_h().clone()),
                    ]
                })
                .collect()
        };

        let (scalars, points): (Vec<Scalar>, Vec<Element>) = per_proof.chain(generators).unzip();

        Element::vartime_multiscalar_mul(&scalars, &points).is_identity()
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
    use crate::{OsRng, Prover, Witness};

    #[test]
    fn empty_batch_fails() {
        let batch = BatchVerifier::new();
        let mut rng = OsRng;
        assert!(batch.verify(&mut rng).is_err());
    }

    #[test]
    fn single_valid_proof() {
        let mut rng = OsRng;
        let params = Parameters::new();
        let x = Scalar::random(&mut rng);
        let witness = Witness::new(x).unwrap();
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
        let mut rng = OsRng;
        let params = Parameters::new();
        let x = Scalar::random(&mut rng);
        let witness = Witness::new(x).unwrap();
        let prover = Prover::new(params.clone(), witness);
        let proof = prover.prove(&mut rng).unwrap();

        let x2 = Scalar::random(&mut rng);
        let wrong_witness = Witness::new(x2).unwrap();
        let wrong_statement = Statement::from_witness(&params, &wrong_witness);

        let mut batch = BatchVerifier::new();
        batch.add(params, wrong_statement, proof).unwrap();

        let results = batch.verify(&mut rng).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }

    #[test]
    fn multiple_valid_proofs() {
        let mut rng = OsRng;
        let params = Parameters::new();
        let mut batch = BatchVerifier::new();

        for _ in 0..10 {
            let x = Scalar::random(&mut rng);
            let witness = Witness::new(x).unwrap();
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
    fn batch_with_distinct_parameters() {
        let mut rng = OsRng;
        let params1 = Parameters::new();
        let params2 =
            Parameters::with_generators(Element::generator_h(), Element::generator_g()).unwrap();

        let mut batch = BatchVerifier::new();
        for params in [params1, params2] {
            let x = Scalar::random(&mut rng);
            let witness = Witness::new(x).unwrap();
            let prover = Prover::new(params.clone(), witness);
            let statement = prover.statement().clone();
            let proof = prover.prove(&mut rng).unwrap();
            batch.add(params, statement, proof).unwrap();
        }

        let results = batch.verify(&mut rng).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[test]
    fn mixed_valid_invalid_proofs() {
        let mut rng = OsRng;
        let params = Parameters::new();
        let mut batch = BatchVerifier::new();

        for i in 0..10 {
            let x = Scalar::random(&mut rng);
            let witness = Witness::new(x).unwrap();
            let prover = Prover::new(params.clone(), witness);
            let proof = prover.prove(&mut rng).unwrap();

            let statement = if i % 2 == 0 {
                prover.statement().clone()
            } else {
                let x2 = Scalar::random(&mut rng);
                let wrong_witness = Witness::new(x2).unwrap();
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
        let mut rng = OsRng;
        let params = Parameters::new();
        let x = Scalar::random(&mut rng);
        let witness = Witness::new(x).unwrap();

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
        let mut rng = OsRng;
        let params = Parameters::new();

        for _ in 0..MAX_BATCH_SIZE {
            let x = Scalar::random(&mut rng);
            let witness = Witness::new(x).unwrap();
            let prover = Prover::new(params.clone(), witness);
            let statement = prover.statement().clone();
            let proof = prover.prove(&mut rng).unwrap();
            assert!(batch.add(params.clone(), statement, proof).is_ok());
        }

        let x = Scalar::random(&mut rng);
        let witness = Witness::new(x).unwrap();
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
        let mut rng = OsRng;
        let params = Parameters::new();
        let mut batch = BatchVerifier::new();

        let x = Scalar::random(&mut rng);
        let witness = Witness::new(x).unwrap();
        let prover = Prover::new(params.clone(), witness);
        let statement = prover.statement().clone();
        let proof = prover.prove(&mut rng).unwrap();
        batch.add(params, statement, proof).unwrap();

        assert!(!batch.is_empty());
        batch.clear();
        assert!(batch.is_empty());
    }
}
