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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OsRng;

    #[test]
    fn generators_are_distinct_and_nontrivial() {
        let g = Element::generator_g();
        let h = Element::generator_h();
        assert_ne!(g, h);
        assert!(!g.is_identity());
        assert!(!h.is_identity());
    }

    #[test]
    fn generator_h_is_stable() {
        assert_eq!(Element::generator_h(), Element::generator_h());
    }

    #[test]
    fn scalar_add_sub_roundtrip() {
        let mut rng = OsRng;
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        assert_eq!(&(&a + &b) - &b, a);
    }

    #[test]
    fn scalar_mul_is_commutative() {
        let mut rng = OsRng;
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        assert_eq!(&a * &b, &b * &a);
    }

    #[test]
    fn scalar_negation_sums_to_zero() {
        let mut rng = OsRng;
        let a = Scalar::random(&mut rng);
        assert!((&a + &(-&a)).is_zero());
    }

    #[test]
    fn scalar_invert_and_zero() {
        let mut rng = OsRng;
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

    #[test]
    fn scalar_ownership_and_assign_variants() {
        let mut rng = OsRng;
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
    fn scalar_bytes_roundtrip() {
        let mut rng = OsRng;
        let s = Scalar::random(&mut rng);
        let bytes = s.to_bytes();

        assert_eq!(Scalar::from_bytes(&bytes).unwrap(), s);
        assert!(Scalar::from_bytes(&bytes[..RISTRETTO_BYTES - 1]).is_err());
    }

    #[test]
    fn element_scalar_mul_distributes_over_scalar_add() {
        let mut rng = OsRng;
        let g = Element::generator_g();
        let s = Scalar::random(&mut rng);
        let t = Scalar::random(&mut rng);

        let gs = &g * &s;
        let gt = &g * &t;

        // `Element * Scalar` is the group's scalar multiplication, so it distributes over addition.
        assert_eq!(&g * &(&s + &t), &gs + &gt);
        assert_eq!((&gs - &gt) + &gt, gs);
    }

    #[test]
    fn element_validate_accepts_valid_point() {
        let mut rng = OsRng;
        let y = &Element::generator_g() * &Scalar::random(&mut rng);
        y.validate().unwrap();
    }

    #[test]
    fn element_bytes_roundtrip() {
        let g = Element::generator_g();
        let bytes = g.to_bytes();

        assert_eq!(Element::from_bytes(&bytes).unwrap(), g);
        assert!(Element::from_bytes(&bytes[..RISTRETTO_BYTES - 1]).is_err());
    }

    #[test]
    fn identity_is_identity() {
        assert!(Element::identity().is_identity());
        assert!(!Element::generator_g().is_identity());
    }
}
