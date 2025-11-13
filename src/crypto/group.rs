use core::fmt::Debug;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::Result;

/// Trait for cryptographic groups used in Chaum-Pedersen protocol.
///
/// This trait defines the interface for groups suitable for zero-knowledge proofs
/// of discrete logarithm equality. Implementations must provide both group operations
/// (for elements) and field operations (for scalars).
pub trait Group: Clone + Debug + Send + Sync + 'static {
    /// Scalar type for this group (exponents/discrete logs).
    ///
    /// Scalars must be zeroizable for security.
    type Scalar: Clone
        + Debug
        + Eq
        + PartialEq
        + Zeroize
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync;

    /// Element type for this group (group elements/points).
    type Element: Clone
        + Debug
        + Eq
        + PartialEq
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync;

    /// Returns the name of this group implementation.
    fn name() -> &'static str;

    /// Returns the first generator `g` for Chaum-Pedersen protocol.
    fn generator_g() -> Self::Element;

    /// Returns the second generator `h` for Chaum-Pedersen protocol.
    ///
    /// Must be independent of `g` (no known discrete log relationship).
    fn generator_h() -> Self::Element;

    /// Deserializes a scalar from bytes.
    fn scalar_from_bytes(b: &[u8]) -> Result<Self::Scalar>;

    /// Serializes a scalar to bytes.
    fn scalar_to_bytes(s: &Self::Scalar) -> Vec<u8>;

    /// Deserializes a group element from bytes.
    fn element_from_bytes(b: &[u8]) -> Result<Self::Element>;

    /// Serializes a group element to bytes.
    fn element_to_bytes(e: &Self::Element) -> Vec<u8>;

    /// Generates a random scalar using the provided RNG.
    fn random_scalar<R: CryptoRngCore>(rng: &mut R) -> Self::Scalar;

    /// Performs scalar multiplication: `element * scalar`.
    fn scalar_mul(e: &Self::Element, s: &Self::Scalar) -> Self::Element;

    /// Multiplies two group elements: `a * b`.
    fn element_mul(a: &Self::Element, b: &Self::Element) -> Self::Element;

    /// Returns the identity element of the group.
    fn identity() -> Self::Element;

    /// Checks if an element is the identity.
    fn is_identity(element: &Self::Element) -> bool;

    /// Validates that an element is in the correct subgroup.
    fn validate_element(e: &Self::Element) -> Result<()>;

    /// Adds two scalars: `a + b`.
    fn scalar_add(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;

    /// Subtracts two scalars: `a - b`.
    fn scalar_sub(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;

    /// Multiplies two scalars: `a * b`.
    fn scalar_mul_scalar(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;

    /// Negates a scalar: `-s`.
    fn scalar_negate(s: &Self::Scalar) -> Self::Scalar;

    /// Computes the multiplicative inverse of a scalar.
    ///
    /// Returns `None` if the scalar is zero.
    fn scalar_invert(s: &Self::Scalar) -> Option<Self::Scalar>;

    /// Checks if a scalar is zero.
    fn scalar_is_zero(s: &Self::Scalar) -> bool;
}
