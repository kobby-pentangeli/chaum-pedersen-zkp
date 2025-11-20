use crypto_bigint::{Encoding, NonZero, Random, U256, U2048, Zero};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::primitives::crypto::field::mod_pow;
use crate::{Error, Group, Result};

/// Number of bytes in a scalar (256 bits).
const SCALAR_BYTES: usize = 32;

/// Number of bytes in a group element (2048 bits).
const ELEMENT_BYTES: usize = 256;

/// RFC 5114 Group implementation using 2048-bit MODP group with 256-bit order subgroup.
#[derive(Clone, Debug)]
pub struct Rfc5114;

/// Scalar in the RFC 5114 group (256-bit integer modulo q).
///
/// Scalars are automatically zeroized when dropped for security.
#[derive(Clone, Debug, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct Scalar(U256);

/// Element in the RFC 5114 group (2048-bit integer modulo p).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Element(U2048);

impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.to_be_bytes().as_ref())
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != SCALAR_BYTES {
            return Err(serde::de::Error::invalid_length(bytes.len(), &"32 bytes"));
        }
        let mut arr = [0u8; SCALAR_BYTES];
        arr.copy_from_slice(&bytes);
        Ok(Scalar(U256::from_be_bytes(arr)))
    }
}

impl Serialize for Element {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.to_be_bytes().as_ref())
    }
}

impl<'de> Deserialize<'de> for Element {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != ELEMENT_BYTES {
            return Err(serde::de::Error::invalid_length(bytes.len(), &"256 bytes"));
        }
        let mut arr = [0u8; ELEMENT_BYTES];
        arr.copy_from_slice(&bytes);
        Ok(Element(U2048::from_be_bytes(arr)))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Scalar {
    /// Creates a new scalar from a U256 value.
    pub fn new(value: U256) -> Self {
        Self(value)
    }

    /// Returns a reference to the inner U256 value.
    pub fn inner(&self) -> &U256 {
        &self.0
    }
}

impl Element {
    /// Creates a new element from a U2048 value.
    pub fn new(value: U2048) -> Self {
        Self(value)
    }

    /// Returns a reference to the inner U2048 value.
    pub fn inner(&self) -> &U2048 {
        &self.0
    }
}

impl Group for Rfc5114 {
    type Scalar = Scalar;
    type Element = Element;

    fn name() -> &'static str {
        "RFC5114-2048-256"
    }

    fn generator_g() -> Self::Element {
        Element(rfc5114_g())
    }

    fn generator_h() -> Self::Element {
        let g = rfc5114_g();
        let p = rfc5114_p();
        let exp = U2048::from_u64(2);
        Element(
            mod_pow(&g, &exp, &p)
                .unwrap_or_else(|_| unreachable!("RFC 5114 constants are valid and p is odd")),
        )
    }

    fn scalar_from_bytes(bytes: &[u8]) -> Result<Self::Scalar> {
        if bytes.len() != SCALAR_BYTES {
            return Err(Error::InvalidScalar(format!(
                "Expected {} bytes, got {}",
                SCALAR_BYTES,
                bytes.len()
            )));
        }

        let value = U256::from_be_slice(bytes);
        let q = rfc5114_q();

        if value >= q {
            return Err(Error::InvalidScalar(
                "Scalar value must be less than group order".to_string(),
            ));
        }

        Ok(Scalar(value))
    }

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.0.to_be_bytes().as_ref().to_vec()
    }

    fn element_from_bytes(bytes: &[u8]) -> Result<Self::Element> {
        if bytes.len() != ELEMENT_BYTES {
            return Err(Error::InvalidGroupElement(format!(
                "Expected {} bytes, got {}",
                ELEMENT_BYTES,
                bytes.len()
            )));
        }

        let value = U2048::from_be_slice(bytes);
        let p = rfc5114_p();

        if value >= p {
            return Err(Error::InvalidGroupElement(
                "Element value must be less than modulus".to_string(),
            ));
        }

        let element = Element(value);
        Self::validate_element(&element)?;
        Ok(element)
    }

    fn element_to_bytes(element: &Self::Element) -> Vec<u8> {
        element.0.to_be_bytes().as_ref().to_vec()
    }

    fn random_scalar<R: CryptoRngCore>(rng: &mut R) -> Self::Scalar {
        let q = rfc5114_q();
        let non_zero_q: Option<NonZero<U256>> = NonZero::new(q).into();
        let non_zero_q = non_zero_q.unwrap_or_else(|| unreachable!("RFC 5114 q is non-zero"));

        loop {
            let value = U256::random(rng);
            let reduced = value.rem(&non_zero_q);

            if !bool::from(reduced.is_zero()) {
                return Scalar(reduced);
            }
        }
    }

    fn scalar_mul(element: &Self::Element, scalar: &Self::Scalar) -> Self::Element {
        let p = rfc5114_p();
        let mut exp_bytes = [0u8; ELEMENT_BYTES];
        let scalar_bytes = scalar.0.to_be_bytes();
        exp_bytes[ELEMENT_BYTES - SCALAR_BYTES..].copy_from_slice(scalar_bytes.as_ref());
        let exp = U2048::from_be_bytes(exp_bytes);
        Element(
            mod_pow(&element.0, &exp, &p)
                .unwrap_or_else(|_| unreachable!("RFC 5114 modulus p is odd")),
        )
    }

    fn element_mul(a: &Self::Element, b: &Self::Element) -> Self::Element {
        let p = rfc5114_p();
        let non_zero_p: Option<NonZero<U2048>> = NonZero::new(p).into();
        let non_zero_p = non_zero_p.unwrap_or_else(|| unreachable!("RFC 5114 p is non-zero"));
        Element(a.0.mul_mod(&b.0, &non_zero_p))
    }

    fn identity() -> Self::Element {
        Element(U2048::ONE)
    }

    fn is_identity(element: &Self::Element) -> bool {
        bool::from(element.0.ct_eq(&U2048::ONE))
    }

    fn validate_element(element: &Self::Element) -> Result<()> {
        let p = rfc5114_p();
        let q = rfc5114_q();

        if element.0 >= p {
            return Err(Error::InvalidGroupElement(
                "Element must be less than p".to_string(),
            ));
        }

        if bool::from(element.0.is_zero()) || bool::from(element.0.ct_eq(&U2048::ONE)) {
            return Ok(());
        }

        let mut q_bytes = [0u8; ELEMENT_BYTES];
        q_bytes[ELEMENT_BYTES - SCALAR_BYTES..].copy_from_slice(q.to_be_bytes().as_ref());
        let q_2048 = U2048::from_be_bytes(q_bytes);
        let result = mod_pow(&element.0, &q_2048, &p)?;
        if !bool::from(result.ct_eq(&U2048::ONE)) {
            return Err(Error::InvalidGroupElement(
                "Element is not in the correct subgroup".to_string(),
            ));
        }

        Ok(())
    }

    fn scalar_add(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        let q = rfc5114_q();
        let non_zero_q: Option<NonZero<U256>> = NonZero::new(q).into();
        let non_zero_q = non_zero_q.unwrap_or_else(|| unreachable!("RFC 5114 q is non-zero"));
        Scalar(a.0.add_mod(&b.0, &non_zero_q))
    }

    fn scalar_sub(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        let q = rfc5114_q();
        let non_zero_q: Option<NonZero<U256>> = NonZero::new(q).into();
        let non_zero_q = non_zero_q.unwrap_or_else(|| unreachable!("RFC 5114 q is non-zero"));
        Scalar(a.0.sub_mod(&b.0, &non_zero_q))
    }

    fn scalar_mul_scalar(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        let q = rfc5114_q();
        let non_zero_q: Option<NonZero<U256>> = NonZero::new(q).into();
        let non_zero_q = non_zero_q.unwrap_or_else(|| unreachable!("RFC 5114 q is non-zero"));
        Scalar(a.0.mul_mod(&b.0, &non_zero_q))
    }

    fn scalar_negate(scalar: &Self::Scalar) -> Self::Scalar {
        let q = rfc5114_q();
        let non_zero_q: Option<NonZero<U256>> = NonZero::new(q).into();
        let non_zero_q = non_zero_q.unwrap_or_else(|| unreachable!("RFC 5114 q is non-zero"));
        Scalar(scalar.0.neg_mod(&non_zero_q))
    }

    fn scalar_invert(scalar: &Self::Scalar) -> Option<Self::Scalar> {
        if Self::scalar_is_zero(scalar) {
            return None;
        }

        let q = rfc5114_q();
        let q_minus_2 = q.wrapping_sub(&U256::from_u8(2));

        let mut exp_bytes = [0u8; ELEMENT_BYTES];
        exp_bytes[ELEMENT_BYTES - SCALAR_BYTES..].copy_from_slice(q_minus_2.to_be_bytes().as_ref());
        let exp_2048 = U2048::from_be_bytes(exp_bytes);

        let mut scalar_bytes = [0u8; ELEMENT_BYTES];
        scalar_bytes[ELEMENT_BYTES - SCALAR_BYTES..]
            .copy_from_slice(scalar.0.to_be_bytes().as_ref());
        let scalar_2048 = U2048::from_be_bytes(scalar_bytes);

        let mut q_bytes = [0u8; ELEMENT_BYTES];
        q_bytes[ELEMENT_BYTES - SCALAR_BYTES..].copy_from_slice(q.to_be_bytes().as_ref());
        let q_2048 = U2048::from_be_bytes(q_bytes);

        let inv_2048 = mod_pow(&scalar_2048, &exp_2048, &q_2048).ok()?;
        let inv_bytes = inv_2048.to_be_bytes();
        let inv =
            U256::from_be_slice(&inv_bytes.as_ref()[inv_bytes.as_ref().len() - SCALAR_BYTES..]);

        Some(Scalar(inv))
    }

    fn scalar_is_zero(scalar: &Self::Scalar) -> bool {
        bool::from(scalar.0.is_zero())
    }
}

fn rfc5114_p() -> U2048 {
    U2048::from_be_hex(
        "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597",
    )
}

/// Returns the RFC 5114 subgroup order q (256-bit prime).
pub fn rfc5114_q() -> U256 {
    U256::from_be_hex("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3")
}

fn rfc5114_g() -> U2048 {
    U2048::from_be_hex(
        "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecureRng;

    #[test]
    fn generators() {
        let g = Rfc5114::generator_g();
        let h = Rfc5114::generator_h();
        assert_ne!(g, h);
    }

    #[test]
    fn scalar_add_sub() {
        let mut rng = SecureRng::new();
        let a = Rfc5114::random_scalar(&mut rng);
        let b = Rfc5114::random_scalar(&mut rng);

        let sum = Rfc5114::scalar_add(&a, &b);
        let diff = Rfc5114::scalar_sub(&sum, &b);
        assert_eq!(a, diff);
    }

    #[test]
    fn scalar_serialization() {
        let mut rng = SecureRng::new();
        let scalar = Rfc5114::random_scalar(&mut rng);
        let bytes = Rfc5114::scalar_to_bytes(&scalar);
        let deserialized = Rfc5114::scalar_from_bytes(&bytes).unwrap();
        assert_eq!(scalar, deserialized);
    }

    #[test]
    fn element_operations() {
        let g = Rfc5114::generator_g();
        let mut rng = SecureRng::new();
        let x = Rfc5114::random_scalar(&mut rng);

        let y = Rfc5114::scalar_mul(&g, &x);
        Rfc5114::validate_element(&y).unwrap();
    }

    #[test]
    fn identity() {
        let id = Rfc5114::identity();
        assert!(Rfc5114::is_identity(&id));

        let g = Rfc5114::generator_g();
        assert!(!Rfc5114::is_identity(&g));
    }
}
