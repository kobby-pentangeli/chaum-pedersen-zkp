use crypto_bigint::{NonZero, U256};
use curve25519_dalek::scalar::Scalar as DalekScalar;
use merlin::Transcript as MerlinTranscript;

use crate::Group;

/// Protocol label for transcript initialization.
const PROTOCOL_LABEL: &[u8] = b"Chaum-Pedersen ZKP v1.0.0";

/// Domain separation tag for protocol name.
const PROTOCOL_DST: &[u8] = b"chaum-pedersen";

/// Domain separation tag for challenge generation.
const CHALLENGE_DST: &[u8] = b"challenge";

/// Number of bytes for wide reduction when generating Ristretto scalars.
const WIDE_REDUCTION_BYTES: usize = 64;

/// Number of extra bits for statistical security in challenge generation (128 bits).
const EXTRA_SECURITY_BITS: usize = 128;

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

    /// Appends the group name to the transcript.
    pub fn append_group_name(&mut self, name: &str) {
        self.0.append_message(b"group", name.as_bytes());
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
    pub fn challenge_scalar_ristretto(&mut self) -> DalekScalar {
        let mut buf = [0u8; WIDE_REDUCTION_BYTES];
        self.0.challenge_bytes(CHALLENGE_DST, &mut buf);
        DalekScalar::from_bytes_mod_order_wide(&buf)
    }

    /// Generates a challenge scalar for RFC 5114 (256-bit modulus q).
    ///
    /// Uses extra bits (128) for statistical security in reduction.
    pub fn challenge_scalar_rfc5114(&mut self, q: &U256) -> U256 {
        let q_bits = q.bits() as usize;
        let byte_len = (q_bits + EXTRA_SECURITY_BITS).div_ceil(8);
        let mut buf = vec![0u8; byte_len];
        self.0.challenge_bytes(CHALLENGE_DST, &mut buf);

        let challenge = U256::from_be_slice(&buf);
        let non_zero_q: Option<NonZero<U256>> = NonZero::new(*q).into();
        let non_zero_q = non_zero_q.unwrap_or_else(|| unreachable!("RFC 5114 q is non-zero"));

        challenge.rem(&non_zero_q)
    }

    /// Generates a challenge scalar for a generic group.
    ///
    /// Dispatches to the appropriate method based on group name.
    pub fn challenge_scalar<G: Group>(&mut self) -> G::Scalar {
        match G::name() {
            "Ristretto255" => {
                let scalar = self.challenge_scalar_ristretto();
                let bytes = scalar.to_bytes();
                G::scalar_from_bytes(&bytes)
                    .unwrap_or_else(|_| unreachable!("Ristretto scalar bytes are valid"))
            }
            "RFC5114-2048-256" => {
                let q = crate::groups::rfc5114::rfc5114_q();
                let challenge = self.challenge_scalar_rfc5114(&q);
                let bytes = challenge.to_be_bytes();
                G::scalar_from_bytes(&bytes)
                    .unwrap_or_else(|_| unreachable!("RFC 5114 scalar bytes are valid"))
            }
            _ => unreachable!("Unknown group: {}", G::name()),
        }
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
    use crate::Ristretto255;

    #[test]
    fn transcript_creation() {
        let transcript = Transcript::new();
        assert!(core::mem::size_of_val(&transcript) > 0);
    }

    #[test]
    fn challenge_scalar_ristretto_deterministic() {
        let mut t1 = Transcript::new();
        t1.append_group_name("test");
        t1.append_parameters(b"g", b"h");
        t1.append_statement(b"y1", b"y2");
        t1.append_commitment(b"r1", b"r2");
        let c1 = t1.challenge_scalar_ristretto();

        let mut t2 = Transcript::new();
        t2.append_group_name("test");
        t2.append_parameters(b"g", b"h");
        t2.append_statement(b"y1", b"y2");
        t2.append_commitment(b"r1", b"r2");
        let c2 = t2.challenge_scalar_ristretto();

        assert_eq!(c1, c2);
    }

    #[test]
    fn challenge_scalar_different_inputs() {
        let mut t1 = Transcript::new();
        t1.append_commitment(b"r1", b"r2");
        let c1 = t1.challenge_scalar_ristretto();

        let mut t2 = Transcript::new();
        t2.append_commitment(b"r1_different", b"r2");
        let c2 = t2.challenge_scalar_ristretto();

        assert_ne!(c1, c2);
    }

    #[test]
    fn generic_challenge_scalar() {
        let mut transcript = Transcript::new();
        transcript.append_group_name(Ristretto255::name());
        let _challenge: <Ristretto255 as Group>::Scalar =
            transcript.challenge_scalar::<Ristretto255>();
    }
}
