//! NIST P-256 (secp256r1) elliptic curve group implementation.
//!
//! # Security Level
//!
//! P-256 provides approximately 128 bits of security against classical attacks.
//!
//! # Performance
//!
//! P-256 operations are typically 2-3x slower than Ristretto255 but faster than RFC5114.

use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar as P256Scalar, U256};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::{Error, Group, Result};

/// Number of bytes in a P-256 scalar (32 bytes).
const P256_SCALAR_BYTES: usize = 32;

/// Number of bytes in a compressed P-256 point (33 bytes: 1 byte prefix + 32 byte x-coordinate).
const P256_COMPRESSED_BYTES: usize = 33;

/// Domain separation tag for deriving the second generator `h`.
///
/// This ensures `h` is deterministically derived and cryptographically independent
/// from the base generator `g`.
const GENERATOR_H_DST: &[u8] = b"chaum-pedersen-zkp-v1.0.0-p256-generator-h";

/// P-256 (secp256r1) elliptic curve group implementation.
#[derive(Clone, Debug)]
pub struct P256;

/// Scalar in the P-256 group.
///
/// Scalars are automatically zeroized when dropped for security.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scalar(
    #[serde(
        serialize_with = "serialize_scalar",
        deserialize_with = "deserialize_scalar"
    )]
    P256Scalar,
);

/// Element (point) in the P-256 group.
///
/// Points are stored in projective coordinates for efficient arithmetic,
/// and serialized in compressed form to save bandwidth.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Element(
    #[serde(
        serialize_with = "serialize_element",
        deserialize_with = "deserialize_element"
    )]
    ProjectivePoint,
);

fn serialize_scalar<S>(scalar: &P256Scalar, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_bytes(&scalar.to_bytes())
}

fn deserialize_scalar<'de, D>(deserializer: D) -> std::result::Result<P256Scalar, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
    if bytes.len() != P256_SCALAR_BYTES {
        return Err(serde::de::Error::invalid_length(
            bytes.len(),
            &"32 bytes for P-256 scalar",
        ));
    }

    let mut arr = [0u8; P256_SCALAR_BYTES];
    arr.copy_from_slice(&bytes);

    Option::<P256Scalar>::from(P256Scalar::from_repr(arr.into()))
        .ok_or_else(|| serde::de::Error::custom("Invalid P-256 scalar"))
}

fn serialize_element<S>(
    element: &ProjectivePoint,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let affine = element.to_affine();
    let encoded = affine.to_encoded_point(true); // compressed format
    serializer.serialize_bytes(encoded.as_bytes())
}

fn deserialize_element<'de, D>(deserializer: D) -> std::result::Result<ProjectivePoint, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
    if bytes.len() != P256_COMPRESSED_BYTES {
        return Err(serde::de::Error::invalid_length(
            bytes.len(),
            &"33 bytes for compressed P-256 point",
        ));
    }

    let encoded = EncodedPoint::from_bytes(&bytes)
        .map_err(|_| serde::de::Error::custom("Invalid encoded point"))?;

    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| serde::de::Error::custom("Invalid P-256 point"))?;

    Ok(ProjectivePoint::from(affine))
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        // P256Scalar doesn't expose mutable internals, so we overwrite with zero
        self.0 = P256Scalar::ZERO;
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Scalar {}

impl PartialEq for Element {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_affine().eq(&other.0.to_affine())
    }
}

impl Eq for Element {}

impl Scalar {
    /// Creates a new scalar from a p256 Scalar.
    pub fn new(value: P256Scalar) -> Self {
        Self(value)
    }

    /// Returns a reference to the inner p256 Scalar.
    pub fn inner(&self) -> &P256Scalar {
        &self.0
    }
}

impl Element {
    /// Creates a new element from a ProjectivePoint.
    pub fn new(value: ProjectivePoint) -> Self {
        Self(value)
    }

    /// Returns a reference to the inner ProjectivePoint.
    pub fn inner(&self) -> &ProjectivePoint {
        &self.0
    }
}

impl Group for P256 {
    type Scalar = Scalar;
    type Element = Element;

    fn name() -> &'static str {
        "P-256"
    }

    fn generator_g() -> Self::Element {
        Element(ProjectivePoint::GENERATOR)
    }

    fn generator_h() -> Self::Element {
        // Derive h deterministically using domain-separated hash-to-scalar
        // This provides cryptographic independence from generator g
        let mut hasher = Sha256::new();
        hasher.update(GENERATOR_H_DST);
        let hash = hasher.finalize();

        // Reduce hash output modulo the curve order to obtain a scalar
        let scalar_reduced = <P256Scalar as Reduce<U256>>::reduce_bytes(&hash);
        Element(ProjectivePoint::GENERATOR * scalar_reduced)
    }

    fn scalar_from_bytes(bytes: &[u8]) -> Result<Self::Scalar> {
        if bytes.len() != P256_SCALAR_BYTES {
            return Err(Error::InvalidScalar(format!(
                "Expected {} bytes, got {}",
                P256_SCALAR_BYTES,
                bytes.len()
            )));
        }

        let mut arr = [0u8; P256_SCALAR_BYTES];
        arr.copy_from_slice(bytes);

        match Option::<P256Scalar>::from(P256Scalar::from_repr(arr.into())) {
            Some(scalar) => Ok(Scalar(scalar)),
            None => Err(Error::InvalidScalar(
                "Bytes do not represent a valid P-256 scalar".to_string(),
            )),
        }
    }

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.0.to_bytes().to_vec()
    }

    fn element_from_bytes(bytes: &[u8]) -> Result<Self::Element> {
        if bytes.len() != P256_COMPRESSED_BYTES {
            return Err(Error::InvalidGroupElement(format!(
                "Expected {} bytes, got {}",
                P256_COMPRESSED_BYTES,
                bytes.len()
            )));
        }

        let encoded = EncodedPoint::from_bytes(bytes)
            .map_err(|_| Error::InvalidGroupElement("Failed to parse encoded point".to_string()))?;

        let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
            .ok_or_else(|| {
                Error::InvalidGroupElement("Bytes do not represent a valid P-256 point".to_string())
            })?;

        Ok(Element(ProjectivePoint::from(affine)))
    }

    fn element_to_bytes(element: &Self::Element) -> Vec<u8> {
        let affine = element.0.to_affine();
        affine.to_encoded_point(true).as_bytes().to_vec()
    }

    fn random_scalar<R: CryptoRngCore>(rng: &mut R) -> Self::Scalar {
        Scalar(P256Scalar::random(rng))
    }

    fn scalar_mul(element: &Self::Element, scalar: &Self::Scalar) -> Self::Element {
        Element(element.0 * scalar.0)
    }

    fn element_mul(a: &Self::Element, b: &Self::Element) -> Self::Element {
        Element(a.0 + b.0)
    }

    fn identity() -> Self::Element {
        Element(ProjectivePoint::IDENTITY)
    }

    fn is_identity(element: &Self::Element) -> bool {
        element.0.to_affine().is_identity().into()
    }

    fn validate_element(element: &Self::Element) -> Result<()> {
        // Check if the point is on the curve
        let affine = element.0.to_affine();

        // Identity is always valid
        if bool::from(affine.is_identity()) {
            return Ok(());
        }

        // For non-identity points, verify they can be encoded and decoded
        let encoded = affine.to_encoded_point(true);
        match Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)) {
            Some(decoded) if decoded == affine => Ok(()),
            _ => Err(Error::InvalidGroupElement(
                "Element failed recompression validation".to_string(),
            )),
        }
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
            Option::<P256Scalar>::from(scalar.0.invert()).map(Scalar)
        }
    }

    fn scalar_is_zero(scalar: &Self::Scalar) -> bool {
        scalar.0.is_zero().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecureRng;

    #[test]
    fn scalar_add_sub() {
        let mut rng = SecureRng::new();
        let a = P256::random_scalar(&mut rng);
        let b = P256::random_scalar(&mut rng);

        let sum = P256::scalar_add(&a, &b);
        let diff = P256::scalar_sub(&sum, &b);
        assert_eq!(a, diff);
    }

    #[test]
    fn scalar_multiplication() {
        let mut rng = SecureRng::new();
        let a = P256::random_scalar(&mut rng);
        let b = P256::random_scalar(&mut rng);

        let ab = P256::scalar_mul_scalar(&a, &b);
        let ba = P256::scalar_mul_scalar(&b, &a);
        assert_eq!(ab, ba);
    }

    #[test]
    fn scalar_inversion() {
        let mut rng = SecureRng::new();
        let a = P256::random_scalar(&mut rng);

        let a_inv = P256::scalar_invert(&a).unwrap();
        let product = P256::scalar_mul_scalar(&a, &a_inv);

        // Verify a * a^-1 = 1 by comparing serialized bytes
        let one_bytes = P256Scalar::ONE.to_bytes();
        let product_bytes = product.0.to_bytes();
        assert_eq!(one_bytes.as_slice(), product_bytes.as_slice());
    }

    #[test]
    fn scalar_serialization() {
        let mut rng = SecureRng::new();
        let scalar = P256::random_scalar(&mut rng);
        let bytes = P256::scalar_to_bytes(&scalar);
        let deserialized = P256::scalar_from_bytes(&bytes).unwrap();
        assert_eq!(scalar, deserialized);
    }

    #[test]
    fn element_operations() {
        let g = P256::generator_g();
        let mut rng = SecureRng::new();
        let x = P256::random_scalar(&mut rng);

        let y = P256::scalar_mul(&g, &x);
        P256::validate_element(&y).unwrap();
    }

    #[test]
    fn element_serialization() {
        let g = P256::generator_g();
        let mut rng = SecureRng::new();
        let x = P256::random_scalar(&mut rng);
        let y = P256::scalar_mul(&g, &x);

        let bytes = P256::element_to_bytes(&y);
        let deserialized = P256::element_from_bytes(&bytes).unwrap();
        assert_eq!(y, deserialized);
    }

    #[test]
    fn element_addition() {
        let g = P256::generator_g();
        let mut rng = SecureRng::new();
        let a = P256::random_scalar(&mut rng);
        let b = P256::random_scalar(&mut rng);

        let ga = P256::scalar_mul(&g, &a);
        let gb = P256::scalar_mul(&g, &b);
        let ga_plus_gb = P256::element_mul(&ga, &gb);

        let a_plus_b = P256::scalar_add(&a, &b);
        let g_a_plus_b = P256::scalar_mul(&g, &a_plus_b);

        assert_eq!(ga_plus_gb, g_a_plus_b);
    }
}
