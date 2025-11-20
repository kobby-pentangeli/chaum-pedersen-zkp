//! Core cryptographic primitives for the Chaum-Pedersen protocol.
//!
//! This module contains all fundamental mathematical and cryptographic building blocks:
//! - **crypto**: Field operations, group trait, and secure randomness
//! - **groups**: Concrete group implementations (Ristretto255, P-256, RFC5114)
//! - **gadgets**: Protocol parameters, statements, witnesses, and proofs
//! - **transcript**: Fiat-Shamir transform for non-interactive proofs

/// Cryptographic primitives and traits.
pub mod crypto;
/// Protocol gadgets (parameters, statements, witnesses, proofs).
pub mod gadgets;
/// Group implementations for Chaum-Pedersen protocol.
pub mod groups;
/// Transcript for Fiat-Shamir transform.
pub mod transcript;

pub use crypto::{Group, SecureRng};
pub use gadgets::{Parameters, Proof, Statement, Witness};
pub use groups::{P256, Rfc5114, Ristretto255};
pub use transcript::Transcript;
