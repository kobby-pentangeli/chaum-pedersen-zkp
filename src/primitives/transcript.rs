//! Fiat-Shamir transcript for non-interactive proofs.
//!
//! Provides domain-separated, transcript-based challenge generation using Merlin.

use curve25519_dalek::scalar::Scalar as DalekScalar;
use merlin::Transcript as MerlinTranscript;

use super::Scalar;

/// Protocol label for transcript initialization.
const PROTOCOL_LABEL: &[u8] = b"Chaum-Pedersen ZKP v1.0.0";

/// Domain separation tag for protocol name.
const PROTOCOL_DST: &[u8] = b"chaum-pedersen-ristretto255";

/// Domain separation tag for challenge generation.
const CHALLENGE_DST: &[u8] = b"challenge";

/// Number of bytes for wide reduction when generating Ristretto scalars.
const WIDE_REDUCTION_BYTES: usize = 64;

/// Transcript wrapper for Fiat-Shamir transformation.
///
/// Provides domain-separated, transcript-based challenge generation using Merlin.
pub struct Transcript(MerlinTranscript);

impl Transcript {
    /// Creates a new transcript for the Chaum-Pedersen protocol.
    pub fn new() -> Self {
        let mut transcript = MerlinTranscript::new(PROTOCOL_LABEL);
        transcript.append_message(b"protocol", PROTOCOL_DST);
        Self(transcript)
    }

    /// Appends application-specific context to prevent cross-protocol attacks.
    ///
    /// # Security
    ///
    /// This should be called before generating proofs in application-specific
    /// contexts to ensure proofs from one context cannot be replayed in another.
    /// Examples: session ID, domain separator, purpose string.
    pub fn append_context(&mut self, context: &[u8]) {
        self.0.append_message(b"context", context);
    }

    /// Appends protocol parameters (generators) to the transcript.
    pub fn append_parameters(&mut self, generator_g: &[u8], generator_h: &[u8]) {
        self.0.append_message(b"generator-g", generator_g);
        self.0.append_message(b"generator-h", generator_h);
    }

    /// Appends the statement (public values) to the transcript.
    pub fn append_statement(&mut self, y1: &[u8], y2: &[u8]) {
        self.0.append_message(b"y1", y1);
        self.0.append_message(b"y2", y2);
    }

    /// Appends the commitment values to the transcript.
    pub fn append_commitment(&mut self, r1: &[u8], r2: &[u8]) {
        self.0.append_message(b"r1", r1);
        self.0.append_message(b"r2", r2);
    }

    /// Generates a challenge scalar for Ristretto255.
    ///
    /// Uses wide reduction (64 bytes) to ensure uniform distribution.
    pub fn challenge_scalar(&mut self) -> Scalar {
        let mut buf = [0u8; WIDE_REDUCTION_BYTES];
        self.0.challenge_bytes(CHALLENGE_DST, &mut buf);
        Scalar::new(DalekScalar::from_bytes_mod_order_wide(&buf))
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_creation() {
        let transcript = Transcript::new();
        assert!(core::mem::size_of_val(&transcript) > 0);
    }

    #[test]
    fn challenge_scalar_deterministic() {
        let mut t1 = Transcript::new();
        t1.append_parameters(b"g", b"h");
        t1.append_statement(b"y1", b"y2");
        t1.append_commitment(b"r1", b"r2");
        let c1 = t1.challenge_scalar();

        let mut t2 = Transcript::new();
        t2.append_parameters(b"g", b"h");
        t2.append_statement(b"y1", b"y2");
        t2.append_commitment(b"r1", b"r2");
        let c2 = t2.challenge_scalar();

        assert_eq!(c1, c2);
    }

    #[test]
    fn challenge_scalar_different_inputs() {
        let mut t1 = Transcript::new();
        t1.append_commitment(b"r1", b"r2");
        let c1 = t1.challenge_scalar();

        let mut t2 = Transcript::new();
        t2.append_commitment(b"r1_different", b"r2");
        let c2 = t2.challenge_scalar();

        assert_ne!(c1, c2);
    }
}
