/// Prover implementation for generating proofs.
pub mod prover;
/// Merlin transcript wrapper for Fiat-Shamir transformation.
pub mod transcript;
/// Core protocol types (parameters, witness, statement, proof).
pub mod types;
/// Verifier implementation for validating proofs.
pub mod verifier;

pub use prover::{Nonce, Prover};
pub use transcript::Transcript;
pub use types::{Commitment, Parameters, Proof, Response, Statement, Witness};
pub use verifier::Verifier;
