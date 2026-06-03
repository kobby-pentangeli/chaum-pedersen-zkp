//! Domain-separation tags defining the Chaum-Pedersen ciphersuite and wire format.
//!
//! Every constant here is a cryptographic input, not a software-version label.
//!
//! Every tag derives from the single [`CIPHERSUITE`] base via [`concat!`], so the scheme is
//! provably consistent.

/// Ciphersuite identifier (protocol name and curve).
macro_rules! ciphersuite {
    () => {
        "chaum-pedersen-zkp/ristretto255"
    };
}

/// The single base every domain tag derives from.
pub const CIPHERSUITE: &str = ciphersuite!();

/// Domain-separation tag deriving the second generator `h` by hash-to-group; fixes `h`'s discrete
/// log to `g` as unknown.
pub(crate) const GENERATOR_H_DST: &[u8] = concat!(ciphersuite!(), "/generator-h").as_bytes();

/// Merlin initialisation label seeding the Fiat-Shamir transcript; binds every challenge to the
/// suite.
pub(crate) const PROTOCOL_LABEL: &[u8] = ciphersuite!().as_bytes();

/// Secondary protocol tag appended to the transcript under [`LABEL_PROTOCOL`].
pub(crate) const PROTOCOL_DST: &[u8] = concat!(ciphersuite!(), "/transcript").as_bytes();

/// Challenge-bytes domain separator for the transcript's scalar challenge.
pub(crate) const CHALLENGE_DST: &[u8] = b"challenge";

pub(crate) const LABEL_PROTOCOL: &[u8] = b"protocol";
pub(crate) const LABEL_CONTEXT: &[u8] = b"context";
pub(crate) const LABEL_GENERATOR_G: &[u8] = b"generator-g";
pub(crate) const LABEL_GENERATOR_H: &[u8] = b"generator-h";
pub(crate) const LABEL_Y1: &[u8] = b"y1";
pub(crate) const LABEL_Y2: &[u8] = b"y2";
pub(crate) const LABEL_R1: &[u8] = b"r1";
pub(crate) const LABEL_R2: &[u8] = b"r2";
