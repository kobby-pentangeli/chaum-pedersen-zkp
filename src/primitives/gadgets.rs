use core::marker::PhantomData;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Group, Result};

/// Protocol version for serialization compatibility.
const PROTOCOL_VERSION: u8 = 1;

/// Public parameters for the Chaum-Pedersen protocol.
///
/// Contains the group generators used for the discrete logarithm equality proof.
/// The protocol proves knowledge of `x` such that `y1 = g^x` and `y2 = h^x`.
///
/// # Security
///
/// The generators `g` and `h` must be cryptographically independent with no known
/// discrete logarithm relationship. Using the default generators from [`Parameters::new()`]
/// is recommended for most applications.
#[derive(Clone, Debug)]
pub struct Parameters<G: Group> {
    generator_g: G::Element,
    generator_h: G::Element,
    _phantom: PhantomData<G>,
}

impl<G: Group> Parameters<G> {
    /// Creates new parameters with the default generators from the group.
    ///
    /// This is the recommended way to create parameters. The default generators
    /// are chosen to be cryptographically independent.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chaum_pedersen::{Parameters, Ristretto255};
    ///
    /// let params = Parameters::<Ristretto255>::new();
    /// ```
    pub fn new() -> Self {
        Self {
            generator_g: G::generator_g(),
            generator_h: G::generator_h(),
            _phantom: PhantomData,
        }
    }

    /// Creates parameters with custom generators.
    ///
    /// # Security
    ///
    /// The generators must be cryptographically independent with no known
    /// discrete log relationship. Both generators must be non-identity elements
    /// and must be different from each other.
    ///
    /// Using custom generators is only recommended for advanced use cases where
    /// the discrete logarithm relationship between `g` and `h` is provably unknown.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Either generator is the identity element
    /// - The generators are equal to each other
    /// - Either generator fails group validation
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chaum_pedersen::{Parameters, Ristretto255, Group};
    ///
    /// let g = <Ristretto255 as Group>::generator_g();
    /// let h = <Ristretto255 as Group>::generator_h();
    /// let params = Parameters::<Ristretto255>::with_generators(g, h).unwrap();
    /// ```
    pub fn with_generators(g: G::Element, h: G::Element) -> Result<Self> {
        G::validate_element(&g)?;
        G::validate_element(&h)?;

        if G::is_identity(&g) {
            return Err(crate::Error::InvalidParams(
                "Generator g cannot be identity".to_string(),
            ));
        }

        if G::is_identity(&h) {
            return Err(crate::Error::InvalidParams(
                "Generator h cannot be identity".to_string(),
            ));
        }

        if g == h {
            return Err(crate::Error::InvalidParams(
                "Generators g and h must be different".to_string(),
            ));
        }

        Ok(Self {
            generator_g: g,
            generator_h: h,
            _phantom: PhantomData,
        })
    }

    /// Returns the first generator `g`.
    pub fn generator_g(&self) -> &G::Element {
        &self.generator_g
    }

    /// Returns the second generator `h`.
    pub fn generator_h(&self) -> &G::Element {
        &self.generator_h
    }
}

impl<G: Group> Default for Parameters<G> {
    fn default() -> Self {
        Self::new()
    }
}

/// Secret witness for the Chaum-Pedersen proof.
///
/// Contains the discrete logarithm `x` that is being proven equal for both generators.
/// The prover demonstrates knowledge of `x` such that `y1 = g^x` and `y2 = h^x` without
/// revealing `x` itself.
///
/// # Security
///
/// - The witness is automatically zeroized when dropped to prevent leakage
/// - Use [`SecureRng`](crate::SecureRng) to generate random witness values
/// - Never reuse witness values across different protocol instances
/// - Keep witness values secret and never transmit them
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Witness<G: Group> {
    x: G::Scalar,
}

impl<G: Group> Witness<G> {
    /// Creates a new witness from a scalar value.
    ///
    /// # Security
    ///
    /// The scalar should be generated using a cryptographically secure random number
    /// generator. Use [`Group::random_scalar`] with [`crate::SecureRng`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chaum_pedersen::{Witness, Ristretto255, Group, SecureRng};
    ///
    /// let mut rng = SecureRng::new();
    /// let x = Ristretto255::random_scalar(&mut rng);
    /// let witness = Witness::<Ristretto255>::new(x);
    /// ```
    pub fn new(x: G::Scalar) -> Self {
        Self { x }
    }

    /// Returns a reference to the secret scalar.
    pub(crate) fn secret(&self) -> &G::Scalar {
        &self.x
    }
}

/// Public statement for the Chaum-Pedersen proof.
///
/// Represents the public values `y1 = g^x` and `y2 = h^x` where `x` is the secret witness.
/// The prover proves knowledge of `x` without revealing it.
///
/// # Security
///
/// - The statement is public and can be safely transmitted
/// - Use [`Statement::validate`] to ensure the values are in the correct subgroup
/// - Statements should be bound to proofs via transcript context to prevent replay attacks
#[derive(Clone, Debug)]
pub struct Statement<G: Group> {
    y1: G::Element,
    y2: G::Element,
}

impl<G: Group> Statement<G> {
    /// Creates a new statement from the public values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chaum_pedersen::{Statement, Ristretto255, Group};
    ///
    /// let g = <Ristretto255 as Group>::generator_g();
    /// let h = <Ristretto255 as Group>::generator_h();
    /// let y1 = g.clone();
    /// let y2 = h.clone();
    ///
    /// let statement = Statement::<Ristretto255>::new(y1, y2);
    /// ```
    pub fn new(y1: G::Element, y2: G::Element) -> Self {
        Self { y1, y2 }
    }

    /// Computes the statement from parameters and witness: `y1 = g^x`, `y2 = h^x`.
    ///
    /// This is the standard way to create a statement from a secret witness.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chaum_pedersen::{Statement, Parameters, Witness, Ristretto255, Group, SecureRng};
    ///
    /// let params = Parameters::<Ristretto255>::new();
    /// let mut rng = SecureRng::new();
    /// let x = Ristretto255::random_scalar(&mut rng);
    /// let witness = Witness::new(x);
    ///
    /// let statement = Statement::from_witness(&params, &witness);
    /// ```
    pub fn from_witness(params: &Parameters<G>, witness: &Witness<G>) -> Self {
        let y1 = G::scalar_mul(params.generator_g(), witness.secret());
        let y2 = G::scalar_mul(params.generator_h(), witness.secret());
        Self { y1, y2 }
    }

    /// Returns the first public value `y1 = g^x`.
    pub fn y1(&self) -> &G::Element {
        &self.y1
    }

    /// Returns the second public value `y2 = h^x`.
    pub fn y2(&self) -> &G::Element {
        &self.y2
    }

    /// Validates that both elements are in the correct subgroup.
    pub fn validate(&self) -> Result<()> {
        G::validate_element(&self.y1)?;
        G::validate_element(&self.y2)?;
        Ok(())
    }
}

/// Commitment values in the Chaum-Pedersen proof.
///
/// First message from prover: `r1 = g^k`, `r2 = h^k` for random `k`.
#[derive(Clone, Debug)]
pub struct Commitment<G: Group> {
    r1: G::Element,
    r2: G::Element,
}

impl<G: Group> Commitment<G> {
    /// Creates a new commitment from the commitment values.
    pub fn new(r1: G::Element, r2: G::Element) -> Self {
        Self { r1, r2 }
    }

    /// Returns the first commitment value `r1 = g^k`.
    pub fn r1(&self) -> &G::Element {
        &self.r1
    }

    /// Returns the second commitment value `r2 = h^k`.
    pub fn r2(&self) -> &G::Element {
        &self.r2
    }
}

/// Response value in the Chaum-Pedersen proof.
///
/// Prover's response to challenge: `s = k + c*x`.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct Response<G: Group> {
    s: G::Scalar,
}

impl<G: Group> Response<G> {
    /// Creates a new response from a scalar value.
    pub fn new(s: G::Scalar) -> Self {
        Self { s }
    }

    /// Returns a reference to the response scalar.
    pub fn s(&self) -> &G::Scalar {
        &self.s
    }
}

/// Complete non-interactive zero-knowledge proof.
///
/// Contains the commitment and response for the Chaum-Pedersen protocol.
/// A proof demonstrates knowledge of `x` such that `y1 = g^x` and `y2 = h^x`
/// without revealing `x`.
///
/// # Security
///
/// - Proofs are single-use and should never be reused
/// - Proofs are bound to the statement via transcript context
/// - Use unique context data (challenge IDs) to prevent replay attacks
/// - Proofs can be safely transmitted and verified by anyone
///
/// # Serialization
///
/// Proofs can be serialized to bytes using [`Proof::to_bytes`] and deserialized
/// using [`Proof::from_bytes`]. The serialization format is versioned for
/// forward compatibility.
#[derive(Clone, Debug)]
pub struct Proof<G: Group> {
    version: u8,
    commitment: Commitment<G>,
    response: Response<G>,
}

impl<G: Group> Proof<G> {
    /// Creates a new proof from commitment and response.
    ///
    /// This is typically called by [`Prover`](crate::Prover) and not directly by users.
    pub fn new(commitment: Commitment<G>, response: Response<G>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            commitment,
            response,
        }
    }

    /// Returns the protocol version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns a reference to the commitment.
    pub fn commitment(&self) -> &Commitment<G> {
        &self.commitment
    }

    /// Returns a reference to the response.
    pub fn response(&self) -> &Response<G> {
        &self.response
    }

    /// Serializes the proof to bytes.
    ///
    /// Format: `[version (1 byte)][r1_len (4 bytes)][r1][r2_len (4 bytes)][r2][s_len (4 bytes)][s]`
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let r1_bytes = G::element_to_bytes(self.commitment.r1());
        let r2_bytes = G::element_to_bytes(self.commitment.r2());
        let s_bytes = G::scalar_to_bytes(self.response.s());

        let mut result = Vec::new();
        result.push(self.version);

        result.extend_from_slice(&(r1_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&r1_bytes);

        result.extend_from_slice(&(r2_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&r2_bytes);

        result.extend_from_slice(&(s_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&s_bytes);

        Ok(result)
    }

    /// Deserializes a proof from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const MAX_ELEMENT_SIZE: usize = 4096;
        const MAX_SCALAR_SIZE: usize = 512;
        const MIN_PROOF_SIZE: usize = 1 + 4 + 1 + 4 + 1 + 4 + 1;

        if bytes.len() < MIN_PROOF_SIZE {
            return Err(crate::Error::InvalidParams(format!(
                "Proof too small: {} bytes",
                bytes.len()
            )));
        }

        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return Err(crate::Error::InvalidParams(format!(
                "Unsupported proof version: {}",
                version
            )));
        }

        let mut pos = 1;

        if pos + 4 > bytes.len() {
            return Err(crate::Error::InvalidParams(
                "Truncated proof: missing r1 length".to_string(),
            ));
        }
        let r1_len = u32::from_be_bytes(
            bytes[pos..pos + 4]
                .try_into()
                .unwrap_or_else(|_| unreachable!("Slice is exactly 4 bytes")),
        ) as usize;
        pos += 4;

        if r1_len == 0 || r1_len > MAX_ELEMENT_SIZE {
            return Err(crate::Error::InvalidParams(format!(
                "Invalid r1 length: {}",
                r1_len
            )));
        }

        if pos + r1_len > bytes.len() {
            return Err(crate::Error::InvalidParams(
                "Truncated proof: incomplete r1 data".to_string(),
            ));
        }
        let r1 = G::element_from_bytes(&bytes[pos..pos + r1_len])?;
        pos += r1_len;

        if pos + 4 > bytes.len() {
            return Err(crate::Error::InvalidParams(
                "Truncated proof: missing r2 length".to_string(),
            ));
        }
        let r2_len = u32::from_be_bytes(
            bytes[pos..pos + 4]
                .try_into()
                .unwrap_or_else(|_| unreachable!("Slice is exactly 4 bytes")),
        ) as usize;
        pos += 4;

        if r2_len == 0 || r2_len > MAX_ELEMENT_SIZE {
            return Err(crate::Error::InvalidParams(format!(
                "Invalid r2 length: {}",
                r2_len
            )));
        }

        if pos + r2_len > bytes.len() {
            return Err(crate::Error::InvalidParams(
                "Truncated proof: incomplete r2 data".to_string(),
            ));
        }
        let r2 = G::element_from_bytes(&bytes[pos..pos + r2_len])?;
        pos += r2_len;

        if pos + 4 > bytes.len() {
            return Err(crate::Error::InvalidParams(
                "Truncated proof: missing s length".to_string(),
            ));
        }
        let s_len = u32::from_be_bytes(
            bytes[pos..pos + 4]
                .try_into()
                .unwrap_or_else(|_| unreachable!("Slice is exactly 4 bytes")),
        ) as usize;
        pos += 4;

        if s_len == 0 || s_len > MAX_SCALAR_SIZE {
            return Err(crate::Error::InvalidParams(format!(
                "Invalid s length: {}",
                s_len
            )));
        }

        if pos + s_len > bytes.len() {
            return Err(crate::Error::InvalidParams(
                "Truncated proof: incomplete s data".to_string(),
            ));
        }
        let s = G::scalar_from_bytes(&bytes[pos..pos + s_len])?;
        pos += s_len;

        if pos != bytes.len() {
            return Err(crate::Error::InvalidParams(format!(
                "Proof has {} trailing bytes",
                bytes.len() - pos
            )));
        }

        G::validate_element(&r1)?;
        G::validate_element(&r2)?;

        if G::is_identity(&r1) || G::is_identity(&r2) {
            return Err(crate::Error::InvalidParams(
                "Commitment contains identity element".to_string(),
            ));
        }

        if G::scalar_is_zero(&s) {
            return Err(crate::Error::InvalidParams(
                "Response scalar is zero".to_string(),
            ));
        }

        Ok(Proof {
            version,
            commitment: Commitment::new(r1, r2),
            response: Response::new(s),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ristretto255, SecureRng};

    #[test]
    fn parameters_default() {
        let params = Parameters::<Ristretto255>::default();
        assert_eq!(params.generator_g(), &Ristretto255::generator_g());
        assert_eq!(params.generator_h(), &Ristretto255::generator_h());
    }

    #[test]
    fn parameters_rejects_identity_generators() {
        let identity = Ristretto255::identity();
        let g = Ristretto255::generator_g();

        assert!(Parameters::<Ristretto255>::with_generators(identity.clone(), g.clone()).is_err());
        assert!(Parameters::<Ristretto255>::with_generators(g.clone(), identity).is_err());
    }

    #[test]
    fn parameters_rejects_equal_generators() {
        let g = Ristretto255::generator_g();
        assert!(Parameters::<Ristretto255>::with_generators(g.clone(), g).is_err());
    }

    #[test]
    fn statement_from_witness() {
        let mut rng = SecureRng::new();
        let params = Parameters::<Ristretto255>::new();
        let x = Ristretto255::random_scalar(&mut rng);
        let witness = Witness::new(x.clone());

        let statement = Statement::from_witness(&params, &witness);
        let expected_y1 = Ristretto255::scalar_mul(params.generator_g(), &x);
        let expected_y2 = Ristretto255::scalar_mul(params.generator_h(), &x);

        assert_eq!(statement.y1(), &expected_y1);
        assert_eq!(statement.y2(), &expected_y2);
    }

    #[test]
    fn proof_serialization() {
        let mut rng = SecureRng::new();
        let r1 = Ristretto255::scalar_mul(
            &Ristretto255::generator_g(),
            &Ristretto255::random_scalar(&mut rng),
        );
        let r2 = Ristretto255::scalar_mul(
            &Ristretto255::generator_h(),
            &Ristretto255::random_scalar(&mut rng),
        );
        let commitment: Commitment<Ristretto255> = Commitment::new(r1, r2);
        let response = Response::new(Ristretto255::random_scalar(&mut rng));
        let proof = Proof::new(commitment, response);

        let bytes = proof.to_bytes().unwrap();
        let deserialized = Proof::<Ristretto255>::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.version(), PROTOCOL_VERSION);
    }

    #[test]
    fn proof_from_bytes_rejects_empty() {
        let result = Proof::<Ristretto255>::from_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_truncated() {
        let result = Proof::<Ristretto255>::from_bytes(&[1, 0, 0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_wrong_version() {
        let mut bytes = vec![99];
        bytes.extend_from_slice(&[0, 0, 0, 32]);
        bytes.resize(100, 0);
        let result = Proof::<Ristretto255>::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_zero_length_fields() {
        let mut bytes = vec![PROTOCOL_VERSION];
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let result = Proof::<Ristretto255>::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_excessive_length() {
        let mut bytes = vec![PROTOCOL_VERSION];
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let result = Proof::<Ristretto255>::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_trailing_data() {
        let mut rng = SecureRng::new();
        let r1 = Ristretto255::scalar_mul(
            &Ristretto255::generator_g(),
            &Ristretto255::random_scalar(&mut rng),
        );
        let r2 = Ristretto255::scalar_mul(
            &Ristretto255::generator_h(),
            &Ristretto255::random_scalar(&mut rng),
        );
        let commitment: Commitment<Ristretto255> = Commitment::new(r1, r2);
        let response = Response::new(Ristretto255::random_scalar(&mut rng));
        let proof = Proof::new(commitment, response);

        let mut bytes = proof.to_bytes().unwrap();
        bytes.push(0xFF);

        let result = Proof::<Ristretto255>::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_identity_commitment() {
        let identity = Ristretto255::identity();
        let mut rng = SecureRng::new();
        let r2 = Ristretto255::scalar_mul(
            &Ristretto255::generator_h(),
            &Ristretto255::random_scalar(&mut rng),
        );

        let commitment: Commitment<Ristretto255> = Commitment::new(identity, r2);
        let response = Response::new(Ristretto255::random_scalar(&mut rng));
        let proof = Proof::new(commitment, response);

        let bytes = proof.to_bytes().unwrap();
        let result = Proof::<Ristretto255>::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_zero_response() {
        let mut rng = SecureRng::new();
        let r1 = Ristretto255::scalar_mul(
            &Ristretto255::generator_g(),
            &Ristretto255::random_scalar(&mut rng),
        );
        let r2 = Ristretto255::scalar_mul(
            &Ristretto255::generator_h(),
            &Ristretto255::random_scalar(&mut rng),
        );
        let commitment: Commitment<Ristretto255> = Commitment::new(r1, r2);

        let zero_scalar = Ristretto255::scalar_from_bytes(&[0u8; 32]).unwrap();
        let response = Response::new(zero_scalar);
        let proof = Proof::new(commitment, response);

        let bytes = proof.to_bytes().unwrap();
        let result = Proof::<Ristretto255>::from_bytes(&bytes);
        assert!(result.is_err());
    }
}
