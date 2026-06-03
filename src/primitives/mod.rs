//! Core cryptographic primitives:
//! Ristretto255 group operations, gadgets, and transcript.

pub(crate) mod domain;
pub mod gadgets;
pub mod ristretto;
pub mod transcript;

pub use domain::CIPHERSUITE;
pub use gadgets::{Commitment, Parameters, Proof, Response, Statement, Witness};
pub use rand_core::OsRng;
pub use ristretto::{Element, Scalar};
pub use transcript::Transcript;
