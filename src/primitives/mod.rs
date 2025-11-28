//! Core cryptographic primitives for the Chaum-Pedersen protocol.
//!
//! This module contains:
//! - [`ristretto`]: Ristretto255 group implementation
//! - [`rng`]: Cryptographically secure random number generator
//! - [`gadgets`]: Protocol data structures (parameters, witness, statement, proof)
//! - [`transcript`]: Fiat-Shamir transcript for non-interactive proofs

/// Ristretto255 group implementation.
pub mod ristretto;

/// Cryptographically secure random number generator.
pub mod rng;

/// Protocol gadgets (parameters, witness, statement, proof).
pub mod gadgets;

/// Fiat-Shamir transcript for non-interactive proofs.
pub mod transcript;

pub use gadgets::{Commitment, Parameters, Proof, Response, Statement, Witness};
pub use ristretto::{Element, Ristretto255, Scalar};
pub use rng::SecureRng;
pub use transcript::Transcript;
