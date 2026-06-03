//! Ristretto255 group implementation for Chaum-Pedersen protocol.
//!
//! Provides fast, prime-order elliptic curve operations based on Curve25519.

use std::sync::LazyLock;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as DalekScalar;
use curve25519_dalek::traits::{Identity, IsIdentity};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::{Error, Result};

/// Number of bytes in a Ristretto255 scalar or compressed element (32 bytes).
const RISTRETTO_BYTES: usize = 32;

/// Number of bytes used for wide scalar reduction (64 bytes).
const WIDE_REDUCTION_BYTES: usize = 64;

/// Domain separation tag for deriving the second generator `h`.
///
/// This ensures `h` is deterministically derived and cryptographically independent
/// from the base generator `g`. Changing this value produces a different generator.
const GENERATOR_H_DST: &[u8] = b"chaum-pedersen-zkp-v1.0.0-generator-h";

// Deriving `h` runs a SHA-512 hash-to-group (Elligator) pass; the result is a constant, so it is
// computed once on first use and shared thereafter rather than recomputed on every call.
static GENERATOR_H: LazyLock<RistrettoPoint> = LazyLock::new(|| {
    let mut hasher = Sha512::new();
    hasher.update(GENERATOR_H_DST);
    RistrettoPoint::from_uniform_bytes(&hasher.finalize().into())
});

/// Ristretto255 group implementation providing fast, prime-order elliptic curve operations.
///
/// This is the recommended group for the Chaum-Pedersen protocol, offering ~128-bit security
/// with excellent performance characteristics.
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

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Scalar {
    /// Creates a new scalar from a curve25519_dalek Scalar.
    pub fn new(value: DalekScalar) -> Self {
        Self(value)
    }

    /// Returns a reference to the inner curve25519_dalek Scalar.
    pub fn inner(&self) -> &DalekScalar {
        &self.0
    }

    /// Samples a uniform scalar by wide reduction of 64 CSPRNG bytes.
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; WIDE_REDUCTION_BYTES];
        rng.fill_bytes(&mut bytes);
        Self(DalekScalar::from_bytes_mod_order_wide(&bytes))
    }

    /// Decodes a 32-byte little-endian scalar; rejects mis-sized input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; RISTRETTO_BYTES] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
        Option::from(DalekScalar::from_canonical_bytes(arr))
            .map(Self)
            .ok_or(Error::InvalidEncoding)
    }

    /// 32-byte little-endian encoding.
    pub fn to_bytes(&self) -> [u8; RISTRETTO_BYTES] {
        self.0.to_bytes()
    }

    /// Multiplicative inverse, or `None` for the zero scalar.
    pub fn invert(&self) -> Option<Self> {
        (!self.is_zero()).then(|| Self(self.0.invert()))
    }

    /// Whether this is the additive-identity (zero) scalar.
    pub fn is_zero(&self) -> bool {
        self.0 == DalekScalar::ZERO
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

    /// First protocol generator `g`, the Ristretto255 basepoint.
    pub fn generator_g() -> Self {
        Self(RISTRETTO_BASEPOINT_TABLE.basepoint())
    }

    /// Second protocol generator `h`, hashed from a domain-separated tag so its discrete log to
    /// `g` is unknown. Memoized after first use.
    pub fn generator_h() -> Self {
        Self(*GENERATOR_H)
    }

    /// The group identity element.
    pub fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }

    /// Whether this is the identity element.
    pub fn is_identity(&self) -> bool {
        self.0.is_identity()
    }

    /// Decodes a compressed element; rejects mis-sized input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; RISTRETTO_BYTES] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
        CompressedRistretto(arr)
            .decompress()
            .map(Self)
            .ok_or(Error::InvalidEncoding)
    }

    /// 32-byte compressed encoding.
    pub fn to_bytes(&self) -> [u8; RISTRETTO_BYTES] {
        self.0.compress().to_bytes()
    }

    /// Confirms the element is a group encoding (rejects malleable points).
    pub fn validate(&self) -> Result<()> {
        if self.0.is_identity() {
            return Ok(());
        }

        match self.0.compress().decompress() {
            Some(point) if point == self.0 => Ok(()),
            _ => Err(Error::InvalidEncoding),
        }
    }
}

// `Scalar` and `Element` wrap Copy inner types but are not themselves Copy (a `Scalar` zeroizes on
// drop), so every operator needs the four owned/borrowed permutations: the borrowed-borrowed form
// is canonical and the rest delegate to it.
macro_rules! impl_binop {
    ($imp:ident, $method:ident, $lhs:ident, $rhs:ident, $out:ident, $op:tt) => {
        impl<'a, 'b> core::ops::$imp<&'b $rhs> for &'a $lhs {
            type Output = $out;
            #[inline]
            fn $method(self, rhs: &'b $rhs) -> $out {
                $out(self.0 $op rhs.0)
            }
        }

        impl<'b> core::ops::$imp<&'b $rhs> for $lhs {
            type Output = $out;
            #[inline]
            fn $method(self, rhs: &'b $rhs) -> $out {
                &self $op rhs
            }
        }

        impl<'a> core::ops::$imp<$rhs> for &'a $lhs {
            type Output = $out;
            #[inline]
            fn $method(self, rhs: $rhs) -> $out {
                self $op &rhs
            }
        }

        impl core::ops::$imp<$rhs> for $lhs {
            type Output = $out;
            #[inline]
            fn $method(self, rhs: $rhs) -> $out {
                &self $op &rhs
            }
        }
    };
}

macro_rules! impl_binop_assign {
    ($imp:ident, $method:ident, $lhs:ident, $rhs:ident, $op:tt) => {
        impl<'b> core::ops::$imp<&'b $rhs> for $lhs {
            #[inline]
            fn $method(&mut self, rhs: &'b $rhs) {
                self.0 $op rhs.0;
            }
        }

        impl core::ops::$imp<$rhs> for $lhs {
            #[inline]
            fn $method(&mut self, rhs: $rhs) {
                self.0 $op rhs.0;
            }
        }
    };
}

macro_rules! impl_neg {
    ($t:ident) => {
        impl core::ops::Neg for $t {
            type Output = $t;
            #[inline]
            fn neg(self) -> $t {
                $t(-self.0)
            }
        }

        impl<'a> core::ops::Neg for &'a $t {
            type Output = $t;
            #[inline]
            fn neg(self) -> $t {
                $t(-self.0)
            }
        }
    };
}

impl_binop!(Add, add, Scalar, Scalar, Scalar, +);
impl_binop!(Sub, sub, Scalar, Scalar, Scalar, -);
impl_binop!(Mul, mul, Scalar, Scalar, Scalar, *);
impl_binop_assign!(AddAssign, add_assign, Scalar, Scalar, +=);
impl_binop_assign!(SubAssign, sub_assign, Scalar, Scalar, -=);
impl_binop_assign!(MulAssign, mul_assign, Scalar, Scalar, *=);
impl_neg!(Scalar);

impl_binop!(Add, add, Element, Element, Element, +);
impl_binop!(Sub, sub, Element, Element, Element, -);
impl_binop!(Mul, mul, Element, Scalar, Element, *);
impl_binop_assign!(AddAssign, add_assign, Element, Element, +=);
impl_binop_assign!(SubAssign, sub_assign, Element, Element, -=);
impl_binop_assign!(MulAssign, mul_assign, Element, Scalar, *=);
impl_neg!(Element);

impl Ristretto255 {
    /// Returns the first generator `g` for Chaum-Pedersen protocol.
    pub fn generator_g() -> Element {
        Element::generator_g()
    }

    /// Returns the second generator `h` for Chaum-Pedersen protocol.
    ///
    /// This generator is independent of `g` (no known discrete log relationship).
    pub fn generator_h() -> Element {
        Element::generator_h()
    }

    /// Deserializes a scalar from bytes.
    pub fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar> {
        Scalar::from_bytes(bytes)
    }

    /// Serializes a scalar to bytes.
    pub fn scalar_to_bytes(scalar: &Scalar) -> Vec<u8> {
        scalar.to_bytes().to_vec()
    }

    /// Deserializes a group element from bytes.
    pub fn element_from_bytes(bytes: &[u8]) -> Result<Element> {
        Element::from_bytes(bytes)
    }

    /// Serializes a group element to bytes.
    pub fn element_to_bytes(element: &Element) -> Vec<u8> {
        element.to_bytes().to_vec()
    }

    /// Generates a random scalar using the provided RNG.
    pub fn random_scalar<R: CryptoRngCore>(rng: &mut R) -> Scalar {
        Scalar::random(rng)
    }

    /// Performs scalar multiplication: `element * scalar`.
    pub fn scalar_mul(element: &Element, scalar: &Scalar) -> Element {
        element * scalar
    }

    /// Multiplies two group elements: `a * b` (group operation is addition).
    pub fn element_mul(a: &Element, b: &Element) -> Element {
        a + b
    }

    /// Returns the identity element of the group.
    pub fn identity() -> Element {
        Element::identity()
    }

    /// Checks if an element is the identity.
    pub fn is_identity(element: &Element) -> bool {
        element.is_identity()
    }

    /// Validates that an element is in the correct subgroup.
    pub fn validate_element(element: &Element) -> Result<()> {
        element.validate()
    }

    /// Adds two scalars: `a + b`.
    pub fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar {
        a + b
    }

    /// Subtracts two scalars: `a - b`.
    pub fn scalar_sub(a: &Scalar, b: &Scalar) -> Scalar {
        a - b
    }

    /// Multiplies two scalars: `a * b`.
    pub fn scalar_mul_scalar(a: &Scalar, b: &Scalar) -> Scalar {
        a * b
    }

    /// Negates a scalar: `-s`.
    pub fn scalar_negate(scalar: &Scalar) -> Scalar {
        -scalar
    }

    /// Computes the multiplicative inverse of a scalar.
    ///
    /// Returns `None` if the scalar is zero.
    pub fn scalar_invert(scalar: &Scalar) -> Option<Scalar> {
        scalar.invert()
    }

    /// Checks if a scalar is zero.
    pub fn scalar_is_zero(scalar: &Scalar) -> bool {
        scalar.is_zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecureRng;

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

    #[test]
    fn scalar_operators_match_free_functions() {
        let mut rng = SecureRng::new();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        assert_eq!(&a + &b, Ristretto255::scalar_add(&a, &b));
        assert_eq!(&a - &b, Ristretto255::scalar_sub(&a, &b));
        assert_eq!(&a * &b, Ristretto255::scalar_mul_scalar(&a, &b));
        assert_eq!(-&a, Ristretto255::scalar_negate(&a));
    }

    #[test]
    fn scalar_ownership_and_assign_variants() {
        let mut rng = SecureRng::new();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let expected = &a + &b;

        assert_eq!(a.clone() + b.clone(), expected);
        assert_eq!(a.clone() + &b, expected);
        assert_eq!(&a + b.clone(), expected);

        let mut acc = a.clone();
        acc += &b;
        assert_eq!(acc, expected);

        let mut acc = a.clone();
        acc += b.clone();
        assert_eq!(acc, expected);
    }

    #[test]
    fn element_operators_match_free_functions() {
        let mut rng = SecureRng::new();
        let g = Element::generator_g();
        let s = Scalar::random(&mut rng);
        let t = Scalar::random(&mut rng);

        let gs = &g * &s;
        let gt = &g * &t;

        assert_eq!(gs, Ristretto255::scalar_mul(&g, &s));
        assert_eq!(&gs + &gt, Ristretto255::element_mul(&gs, &gt));

        // `Element * Scalar` is the group's scalar multiplication, so it distributes over scalar add.
        assert_eq!(&g * &(&s + &t), &gs + &gt);
        assert_eq!((&gs - &gt) + &gt, gs);
    }

    #[test]
    fn scalar_bytes_roundtrip() {
        let mut rng = SecureRng::new();
        let s = Scalar::random(&mut rng);
        let bytes = s.to_bytes();

        assert_eq!(Scalar::from_bytes(&bytes).unwrap(), s);
        assert!(Scalar::from_bytes(&bytes[..RISTRETTO_BYTES - 1]).is_err());
    }

    #[test]
    fn element_bytes_roundtrip() {
        let g = Element::generator_g();
        let bytes = g.to_bytes();

        assert_eq!(Element::from_bytes(&bytes).unwrap(), g);
        assert!(Element::from_bytes(&bytes[..RISTRETTO_BYTES - 1]).is_err());
    }

    #[test]
    fn generator_h_is_stable() {
        assert_eq!(Element::generator_h(), Element::generator_h());
        assert_ne!(Element::generator_h(), Element::generator_g());
    }

    #[test]
    fn scalar_invert_and_zero() {
        let mut rng = SecureRng::new();
        let a = Scalar::random(&mut rng);

        let product = &a * &a.invert().unwrap();
        let mut one = [0u8; RISTRETTO_BYTES];
        one[0] = 1;
        assert_eq!(product.to_bytes(), one);

        let zero = Scalar::from_bytes(&[0u8; RISTRETTO_BYTES]).unwrap();
        assert!(zero.is_zero());
        assert!(zero.invert().is_none());
        assert!(!a.is_zero());
    }
}
