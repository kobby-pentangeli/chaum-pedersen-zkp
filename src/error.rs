//! Error types for the Chaum-Pedersen protocol.

/// Errors arising from the core protocol: parameter validation, scalar and
/// group-element encoding, proof serialization, and verification.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("proof verification failed")]
    VerificationFailed,

    #[error("group element is the identity")]
    IdentityElement,

    #[error("invalid scalar or group-element encoding")]
    InvalidEncoding,

    #[error("malformed proof encoding")]
    Deserialization,

    #[error("invalid protocol parameters")]
    InvalidParameters,

    #[error("batch contains no proofs")]
    BatchEmpty,

    #[error("batch size {actual} exceeds the maximum of {max}")]
    BatchSizeExceeded {
        /// Maximum number of proofs a single batch may hold.
        max: usize,
        /// Number of proofs the batch would have held.
        actual: usize,
    },
}

/// Errors from the in-memory server state: the user registry, challenge tracking,
/// and session management.
#[cfg(feature = "server")]
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("user already registered")]
    UserAlreadyExists,

    #[error("user not found")]
    UserNotFound,

    #[error("invalid or expired challenge")]
    ChallengeNotFound,

    #[error("invalid or expired session")]
    SessionNotFound,

    #[error("too many active challenges for user")]
    TooManyChallenges,

    #[error("too many active sessions for user")]
    TooManySessions,

    #[error("server capacity reached for {resource}")]
    CapacityExceeded {
        /// The exhausted resource: `"users"`, `"challenges"`, or `"sessions"`.
        resource: &'static str,
    },
}
