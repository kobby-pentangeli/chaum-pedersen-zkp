//! # Chaum-Pedersen Zero-Knowledge Protocol Library
//!
//! ## Overview
//!
//! The Chaum-Pedersen protocol allows a prover to demonstrate knowledge of a discrete logarithm
//! `x` such that `y1 = g^x` and `y2 = h^x` without revealing `x` itself. This implementation
//! supports both interactive and non-interactive (Fiat-Shamir) proof variants.
//!
//! ## Features
//!
//! - **Ristretto255 implementation**: Fast, prime-order elliptic curve group
//! - **Constant-time operations**: Protection against timing attacks
//! - **Memory zeroization**: Automatic clearing of sensitive data
//! - **Fiat-Shamir transform**: Non-interactive proofs with transcript support
//! - **gRPC support**: Optional client-server authentication system
//! - **Batch verification**: Efficient verification of multiple proofs
//!
//! ## Quick Start
//!
//! ```rust
//! use chaum_pedersen::{
//!     Ristretto255, SecureRng, Parameters, Witness, Statement, Prover, Verifier, Transcript
//! };
//!
//! let params = Parameters::new();
//! let mut rng = SecureRng::new();
//!
//! // Prover: Generate secret and create statement
//! let x = Ristretto255::random_scalar(&mut rng);
//! let witness = Witness::new(x);
//! let statement = Statement::from_witness(&params, &witness);
//!
//! // Prover: Generate proof with Fiat-Shamir
//! let mut transcript = Transcript::new();
//! let proof = Prover::new(params.clone(), witness)
//!     .prove_with_transcript(&mut rng, &mut transcript)
//!     .unwrap();
//!
//! // Verifier: Verify the proof
//! let mut verify_transcript = Transcript::new();
//! let verifier = Verifier::new(params, statement);
//! assert!(verifier.verify_with_transcript(&proof, &mut verify_transcript).is_ok());
//! ```
//!
//! ## Security Considerations
//!
//! - **Randomness**: Use `SecureRng` for all random scalar generation
//! - **Transcript binding**: Use unique context data to prevent replay attacks
//! - **Single-use challenges**: Never reuse challenges or proofs across sessions
//! - **Constant-time**: All group operations are designed to resist timing attacks
//!
//! ## Performance
//!
//! Benchmark results on M-series Mac:
//! - Proof generation: ~144 microseconds
//! - Proof verification: ~159 microseconds
//! - Serialization/deserialization: ~7 microseconds
//!
//! ## Feature Flags
//!
//! - `server`: Enable server-side state management
//! - `grpc`: Enable gRPC service definitions and implementations

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod error;
pub mod primitives;
pub mod prover;
pub mod verifier;

#[cfg(feature = "grpc")]
/// Generated protobuf types.
#[allow(missing_docs)]
pub mod proto {
    include!("auth.rs");
}

pub use error::Error;
pub use primitives::{
    Commitment, Element, Parameters, Proof, Response, Ristretto255, Scalar, SecureRng, Statement,
    Transcript, Witness,
};
pub use prover::Prover;
pub use verifier::{BatchVerifier, Verifier};

/// Result type for Chaum-Pedersen operations.
pub type Result<T> = core::result::Result<T, Error>;
