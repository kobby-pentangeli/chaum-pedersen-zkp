/// Core protocol types (parameters, witness, statement, proof).
pub mod gadgets;
/// Prover implementation for generating proofs.
pub mod prover;
/// Merlin transcript wrapper for Fiat-Shamir transformation.
pub mod transcript;
/// Verifier implementation for validating proofs.
pub mod verifier;

pub use gadgets::{Commitment, Parameters, Proof, Response, Statement, Witness};
pub use prover::{Nonce, Prover};
pub use transcript::Transcript;
pub use verifier::Verifier;
