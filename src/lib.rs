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
//! - **Multiple group implementations**: RFC 5114 MODP and Ristretto255
//! - **Constant-time operations**: Protection against timing attacks
//! - **Memory zeroization**: Automatic clearing of sensitive data
//! - **Fiat-Shamir transform**: Non-interactive proofs with transcript support
//! - **gRPC support**: Optional client-server authentication system
//!
//! ## Quick Start
//!
//! ```rust
//! use chaum_pedersen::{
//!     Ristretto255, Group, SecureRng, Parameters, Witness, Statement, Prover, Verifier, Transcript
//! };
//!
//! let params = Parameters::<Ristretto255>::new();
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
//! - **Group selection**: Use Ristretto255 for best security and performance
//! - **Randomness**: Use `SecureRng` for all random scalar generation
//! - **Transcript binding**: Use unique context data to prevent replay attacks
//! - **Single-use challenges**: Never reuse challenges or proofs across sessions
//! - **Constant-time**: All group operations are designed to resist timing attacks
//!
//! ## Performance
//!
//! Benchmark results on M-series Mac (Ristretto255):
//! - Proof generation: ~144 microseconds
//! - Proof verification: ~159 microseconds
//! - Serialization/deserialization: ~7 microseconds
//!
//! RFC5114 is approximately 100x slower than Ristretto255 and is not recommended
//! for new applications.
//!
//! ## Feature Flags
//!
//! - `server`: Enable server-side state management
//! - `grpc`: Enable gRPC service definitions and implementations

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

/// Cryptographic primitives and traits.
pub mod crypto;
/// Error types for the library.
pub mod error;
/// Group implementations for Chaum-Pedersen protocol.
pub mod groups;
/// Protocol implementation (prover, verifier, transcripts).
pub mod protocol;

#[cfg(feature = "server")]
/// Server-side implementation.
pub mod server;

#[cfg(feature = "grpc")]
/// Generated protobuf types.
#[allow(missing_docs)]
pub mod proto {
    tonic::include_proto!("chaum_pedersen.v1");
}

pub use crypto::{Group, SecureRng};
pub use error::Error;
pub use groups::{Rfc5114, Ristretto255};
pub use protocol::{Parameters, Proof, Prover, Statement, Transcript, Verifier, Witness};

/// A specialized Result type for Chaum-Pedersen operations.
pub type Result<T> = core::result::Result<T, Error>;
