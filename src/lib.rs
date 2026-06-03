//! # Chaum-Pedersen Zero-Knowledge Protocol
//!
//! Prove knowledge of a discrete logarithm `x` with `y1 = g^x` and `y2 = h^x` without revealing
//! `x`, over Ristretto255. Supports interactive and non-interactive (Fiat-Shamir) variants, batch
//! verification, and an optional gRPC authentication service.
//!
//! ## Quick start
//!
//! ```rust
//! use chaum_pedersen::{
//!     OsRng, Parameters, Prover, Scalar, Statement, Transcript, Verifier, Witness,
//! };
//!
//! let params = Parameters::new();
//! let mut rng = OsRng;
//!
//! let x = Scalar::random(&mut rng);
//! let witness = Witness::new(x).unwrap();
//! let statement = Statement::from_witness(&params, &witness);
//!
//! let mut transcript = Transcript::new();
//! let proof = Prover::new(params.clone(), witness)
//!     .prove_with_transcript(&mut rng, &mut transcript)
//!     .unwrap();
//!
//! let mut verify_transcript = Transcript::new();
//! let verifier = Verifier::new(params, statement);
//! assert!(verifier.verify_with_transcript(&proof, &mut verify_transcript).is_ok());
//! ```
//!
//! Bind each proof to a unique transcript context to prevent replay; witnesses and nonces are
//! zeroized on drop.
//!
//! ## Feature flags
//!
//! - `server`: server-side state management and the gRPC service.
//! - `client`: the gRPC client.
//! - `grpc`: gRPC definitions shared by `server` and `client`.

#![forbid(unsafe_code)]
#![warn(clippy::all)]

pub mod error;
pub mod primitives;
pub mod prover;
pub mod verifier;

#[cfg(feature = "grpc")]
/// Generated protobuf types.
#[allow(missing_docs)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/auth.rs"));
}

pub use error::Error;
#[cfg(feature = "server")]
pub use error::StateError;
pub use primitives::{
    Commitment, Element, OsRng, Parameters, Proof, Response, Scalar, Statement, Transcript, Witness,
};
pub use prover::Prover;
pub use verifier::{BatchVerifier, Verifier};

/// Result type for Chaum-Pedersen operations.
pub type Result<T> = core::result::Result<T, Error>;
