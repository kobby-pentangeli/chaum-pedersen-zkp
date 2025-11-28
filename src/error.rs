//! Error types for Chaum-Pedersen

/// Main error types for the library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid group parameters were provided.
    #[error("Invalid group parameters: {0}")]
    InvalidParams(String),

    /// A scalar value is invalid or out of range.
    #[error("Invalid scalar: {0}")]
    InvalidScalar(String),

    /// A group element is invalid or not in the correct subgroup.
    #[error("Invalid group element: {0}")]
    InvalidGroupElement(String),
}
