/// RFC 5114 MODP group implementation (2048-bit, 256-bit order).
pub mod rfc5114;
/// Ristretto255 group implementation (fast, modern elliptic curve).
pub mod ristretto;

pub use rfc5114::Rfc5114;
pub use ristretto::Ristretto255;
