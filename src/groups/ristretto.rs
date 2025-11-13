use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as DalekScalar;
use curve25519_dalek::traits::Identity;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::{Error, Group, Result};

/// Number of bytes in a Ristretto255 scalar or compressed element (32 bytes).
const RISTRETTO_BYTES: usize = 32;

/// Number of bytes used for wide scalar reduction (64 bytes).
const WIDE_REDUCTION_BYTES: usize = 64;

/// Domain separation tag for deriving the second generator `h`.
///
/// This ensures `h` is deterministically derived and cryptographically independent
/// from the base generator `g`. Changing this value produces a different generator.
const GENERATOR_H_DST: &[u8] = b"chaum-pedersen-zkp-v1.0.0-generator-h";

/// Ristretto255 group implementation providing fast, prime-order elliptic curve operations.
#[derive(Clone, Debug)]
pub struct Ristretto255;

/// Scalar in the Ristretto255 group.
///
/// Scalars are automatically zeroized when dropped for security.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct Scalar(DalekScalar);

/// Element (point) in the Ristretto255 group.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Element(RistrettoPoint);

impl Scalar {
    /// Creates a new scalar from a curve25519_dalek Scalar.
    pub fn new(value: DalekScalar) -> Self {
        Self(value)
    }

    /// Returns a reference to the inner curve25519_dalek Scalar.
    pub fn inner(&self) -> &DalekScalar {
        &self.0
    }
}

impl Element {
    /// Creates a new element from a RistrettoPoint.
    pub fn new(value: RistrettoPoint) -> Self {
        Self(value)
    }

    /// Returns a reference to the inner RistrettoPoint.
    pub fn inner(&self) -> &RistrettoPoint {
        &self.0
    }
}

impl Group for Ristretto255 {
    type Scalar = Scalar;
    type Element = Element;

    fn name() -> &'static str {
        "Ristretto255"
    }

    fn generator_g() -> Self::Element {
        Element(RISTRETTO_BASEPOINT_TABLE.basepoint())
    }

    fn generator_h() -> Self::Element {
        let mut hasher = Sha512::new();
        hasher.update(GENERATOR_H_DST);
        let hash = hasher.finalize();
        Element(RistrettoPoint::from_uniform_bytes(&hash.into()))
    }

    fn scalar_from_bytes(bytes: &[u8]) -> Result<Self::Scalar> {
        if bytes.len() != RISTRETTO_BYTES {
            return Err(Error::InvalidScalar(format!(
                "Expected {} bytes, got {}",
                RISTRETTO_BYTES,
                bytes.len()
            )));
        }

        let mut arr = [0u8; RISTRETTO_BYTES];
        arr.copy_from_slice(bytes);

        match DalekScalar::from_canonical_bytes(arr).into() {
            Some(scalar) => Ok(Scalar(scalar)),
            None => Err(Error::InvalidScalar(
                "Bytes do not represent a valid scalar".to_string(),
            )),
        }
    }

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.0.to_bytes().to_vec()
    }

    fn element_from_bytes(bytes: &[u8]) -> Result<Self::Element> {
        if bytes.len() != RISTRETTO_BYTES {
            return Err(Error::InvalidGroupElement(format!(
                "Expected {} bytes, got {}",
                RISTRETTO_BYTES,
                bytes.len()
            )));
        }

        let mut arr = [0u8; RISTRETTO_BYTES];
        arr.copy_from_slice(bytes);

        match CompressedRistretto(arr).decompress() {
            Some(point) => Ok(Element(point)),
            None => Err(Error::InvalidGroupElement(
                "Bytes do not represent a valid Ristretto point".to_string(),
            )),
        }
    }

    fn element_to_bytes(element: &Self::Element) -> Vec<u8> {
        element.0.compress().to_bytes().to_vec()
    }

    fn random_scalar<R: CryptoRngCore>(rng: &mut R) -> Self::Scalar {
        let mut bytes = [0u8; WIDE_REDUCTION_BYTES];
        rng.fill_bytes(&mut bytes);
        Scalar(DalekScalar::from_bytes_mod_order_wide(&bytes))
    }

    fn scalar_mul(element: &Self::Element, scalar: &Self::Scalar) -> Self::Element {
        Element(element.0 * scalar.0)
    }

    fn element_mul(a: &Self::Element, b: &Self::Element) -> Self::Element {
        Element(a.0 + b.0)
    }

    fn identity() -> Self::Element {
        Element(RistrettoPoint::identity())
    }

    fn is_identity(element: &Self::Element) -> bool {
        element.0 == RistrettoPoint::identity()
    }

    fn validate_element(_element: &Self::Element) -> Result<()> {
        Ok(())
    }

    fn scalar_add(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        Scalar(a.0 + b.0)
    }

    fn scalar_sub(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        Scalar(a.0 - b.0)
    }

    fn scalar_mul_scalar(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        Scalar(a.0 * b.0)
    }

    fn scalar_negate(scalar: &Self::Scalar) -> Self::Scalar {
        Scalar(-scalar.0)
    }

    fn scalar_invert(scalar: &Self::Scalar) -> Option<Self::Scalar> {
        if Self::scalar_is_zero(scalar) {
            None
        } else {
            Some(Scalar(scalar.0.invert()))
        }
    }

    fn scalar_is_zero(scalar: &Self::Scalar) -> bool {
        scalar.0 == DalekScalar::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecureRng;

    #[test]
    fn generators() {
        let g = Ristretto255::generator_g();
        let h = Ristretto255::generator_h();
        assert_ne!(g, h);
        assert!(!Ristretto255::is_identity(&g));
        assert!(!Ristretto255::is_identity(&h));
    }

    #[test]
    fn scalar_add_sub() {
        let mut rng = SecureRng::new();
        let a = Ristretto255::random_scalar(&mut rng);
        let b = Ristretto255::random_scalar(&mut rng);

        let sum = Ristretto255::scalar_add(&a, &b);
        let diff = Ristretto255::scalar_sub(&sum, &b);
        assert_eq!(a, diff);
    }

    #[test]
    fn scalar_multiplication() {
        let mut rng = SecureRng::new();
        let a = Ristretto255::random_scalar(&mut rng);
        let b = Ristretto255::random_scalar(&mut rng);

        let ab = Ristretto255::scalar_mul_scalar(&a, &b);
        let ba = Ristretto255::scalar_mul_scalar(&b, &a);
        assert_eq!(ab, ba);
    }

    #[test]
    fn scalar_inversion() {
        let mut rng = SecureRng::new();
        let a = Ristretto255::random_scalar(&mut rng);

        let a_inv = Ristretto255::scalar_invert(&a).unwrap();
        let product = Ristretto255::scalar_mul_scalar(&a, &a_inv);

        let one_bytes = DalekScalar::ONE.to_bytes();
        let product_bytes = product.0.to_bytes();
        assert_eq!(one_bytes, product_bytes);
    }

    #[test]
    fn scalar_serialization() {
        let mut rng = SecureRng::new();
        let scalar = Ristretto255::random_scalar(&mut rng);
        let bytes = Ristretto255::scalar_to_bytes(&scalar);
        let deserialized = Ristretto255::scalar_from_bytes(&bytes).unwrap();
        assert_eq!(scalar, deserialized);
    }

    #[test]
    fn element_operations() {
        let g = Ristretto255::generator_g();
        let mut rng = SecureRng::new();
        let x = Ristretto255::random_scalar(&mut rng);

        let y = Ristretto255::scalar_mul(&g, &x);
        Ristretto255::validate_element(&y).unwrap();
    }

    #[test]
    fn element_serialization() {
        let g = Ristretto255::generator_g();
        let mut rng = SecureRng::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let y = Ristretto255::scalar_mul(&g, &x);

        let bytes = Ristretto255::element_to_bytes(&y);
        let deserialized = Ristretto255::element_from_bytes(&bytes).unwrap();
        assert_eq!(y, deserialized);
    }

    #[test]
    fn identity() {
        let id = Ristretto255::identity();
        assert!(Ristretto255::is_identity(&id));

        let g = Ristretto255::generator_g();
        assert!(!Ristretto255::is_identity(&g));
    }

    #[test]
    fn element_addition() {
        let g = Ristretto255::generator_g();
        let mut rng = SecureRng::new();
        let a = Ristretto255::random_scalar(&mut rng);
        let b = Ristretto255::random_scalar(&mut rng);

        let ga = Ristretto255::scalar_mul(&g, &a);
        let gb = Ristretto255::scalar_mul(&g, &b);
        let ga_plus_gb = Ristretto255::element_mul(&ga, &gb);

        let a_plus_b = Ristretto255::scalar_add(&a, &b);
        let g_a_plus_b = Ristretto255::scalar_mul(&g, &a_plus_b);

        assert_eq!(ga_plus_gb, g_a_plus_b);
    }
}
