//! # Chaum-Pedersen Zero-Knowledge Protocol Library
//!
//! An implementation of the Chaum-Pedersen zero-knowledge protocol,
//! enabling proofs of discrete logarithm equality.
//!
//! ## Features
//!
//! - Multiple group implementations (RFC 5114 MODP, Ristretto255)
//! - Constant-time operations to prevent timing attacks
//! - Memory zeroization for sensitive data
//! - Interactive and non-interactive (Fiat-Shamir) proof variants
//!
//! ## Example
//!
//! ```rust
//! use chaum_pedersen::Ristretto255;
//! use chaum_pedersen::{Group, SecureRng};
//!
//! let mut rng = SecureRng::new();
//!
//! // Generate secret
//! let x = Ristretto255::random_scalar(&mut rng);
//!
//! // Compute public values
//! let g = Ristretto255::generator_g();
//! let h = Ristretto255::generator_h();
//! let y1 = Ristretto255::scalar_mul(&g, &x);
//! let y2 = Ristretto255::scalar_mul(&h, &x);
//! ```

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
