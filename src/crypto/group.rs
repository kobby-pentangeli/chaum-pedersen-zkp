use core::fmt::Debug;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::Result;

pub trait Group: Clone + Debug + Send + Sync + 'static {
    type Scalar: Clone
        + Debug
        + Eq
        + PartialEq
        + Zeroize
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync;
    type Element: Clone
        + Debug
        + Eq
        + PartialEq
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync;

    fn name() -> &'static str;

    fn generator_g() -> Self::Element;

    fn generator_h() -> Self::Element;

    fn scalar_from_bytes(b: &[u8]) -> Result<Self::Scalar>;

    fn scalar_to_bytes(s: &Self::Scalar) -> Vec<u8>;

    fn element_from_bytes(b: &[u8]) -> Result<Self::Element>;

    fn element_to_bytes(e: &Self::Element) -> Vec<u8>;

    fn random_scalar<R: CryptoRngCore>(rng: &mut R) -> Self::Scalar;

    fn scalar_mul(e: &Self::Element, s: &Self::Scalar) -> Self::Element;

    fn element_mul(a: &Self::Element, b: &Self::Element) -> Self::Element;

    fn identity() -> Self::Element;

    fn is_identity(element: &Self::Element) -> bool;

    fn validate_element(e: &Self::Element) -> Result<()>;

    fn scalar_add(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;

    fn scalar_sub(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;

    fn scalar_mul_scalar(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;

    fn scalar_negate(s: &Self::Scalar) -> Self::Scalar;

    fn scalar_invert(s: &Self::Scalar) -> Option<Self::Scalar>;

    fn scalar_is_zero(s: &Self::Scalar) -> bool;
}
