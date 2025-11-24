//! Cryptographically secure random number generator.

use rand_core::{CryptoRng, OsRng, RngCore};

/// Cryptographically secure random number generator.
///
/// This is a thin wrapper around `OsRng` that provides a consistent interface
/// for cryptographic randomness throughout the library.
pub struct SecureRng(OsRng);

impl SecureRng {
    /// Creates a new cryptographically secure random number generator.
    pub fn new() -> Self {
        Self(OsRng)
    }
}

impl Default for SecureRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for SecureRng {}
