use crypto_bigint::modular::{MontyForm, MontyParams};
use crypto_bigint::{Odd, Uint, Zero};

use crate::{Error, Result};

/// Performs modular exponentiation using Montgomery form.
///
/// Computes `base^exp mod modulus` in constant time.
///
/// # Security Note
///
/// Uses `new_vartime` for parameter setup, which is acceptable because:
/// - The modulus is public (RFC 5114 constants p and q)
/// - Timing variations occur only during setup, not during exponentiation
/// - The actual `pow()` operation is constant-time
pub fn mod_pow<const LIMBS: usize>(
    base: &Uint<LIMBS>,
    exp: &Uint<LIMBS>,
    modulus: &Uint<LIMBS>,
) -> Result<Uint<LIMBS>> {
    if modulus.is_zero().into() {
        return Err(Error::InvalidParams("modulus cannot be zero".to_string()));
    }

    let odd_modulus: Option<Odd<Uint<LIMBS>>> = Odd::new(*modulus).into();
    let odd_modulus = odd_modulus.ok_or_else(|| {
        Error::InvalidParams("modulus must be odd for Montgomery form".to_string())
    })?;

    let params = MontyParams::new_vartime(odd_modulus);
    let base_monty = MontyForm::new(base, params);
    let result = base_monty.pow(exp);
    Ok(result.retrieve())
}
