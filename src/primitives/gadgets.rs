//! Core protocol data structures: parameters, witness, statement, commitment, response, proof.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{Element, Scalar};
use crate::{Error, Result};

const PROTOCOL_VERSION: u8 = 1;

/// Public parameters: the two group generators `g`, `h` for the discrete-log-equality proof.
///
/// `g` and `h` must be cryptographically independent (no known discrete-log relation);
/// [`Parameters::new`] supplies suitable defaults.
#[derive(Clone, Debug)]
pub struct Parameters {
    generator_g: Element,
    generator_h: Element,
}

impl Parameters {
    /// Creates parameters with the default, independent group generators (recommended).
    pub fn new() -> Self {
        Self {
            generator_g: Element::generator_g(),
            generator_h: Element::generator_h(),
        }
    }

    /// Creates parameters from custom generators, which must be independent, non-identity, and
    /// distinct. Errors on an identity, equal, or otherwise invalid generator.
    pub fn with_generators(g: Element, h: Element) -> Result<Self> {
        g.validate()?;
        h.validate()?;

        if g.is_identity() || h.is_identity() || g == h {
            return Err(Error::InvalidParameters);
        }

        Ok(Self {
            generator_g: g,
            generator_h: h,
        })
    }

    pub fn generator_g(&self) -> &Element {
        &self.generator_g
    }

    pub fn generator_h(&self) -> &Element {
        &self.generator_h
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Self::new()
    }
}

/// Secret witness: the discrete logarithm `x` with `y1 = g^x`, `y2 = h^x`. Zeroized on drop;
/// never reuse or transmit it.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Witness {
    x: Scalar,
}

impl Witness {
    /// Wraps a secret scalar; generate it with a CSPRNG ([`Scalar::random`]).
    pub fn new(x: Scalar) -> Self {
        Self { x }
    }

    pub(crate) fn secret(&self) -> &Scalar {
        &self.x
    }
}

/// Public statement: the values `y1 = g^x`, `y2 = h^x`. Safe to transmit; bind it to proofs via
/// the transcript to prevent replay.
#[derive(Clone, Debug)]
pub struct Statement {
    y1: Element,
    y2: Element,
}

impl Statement {
    pub fn new(y1: Element, y2: Element) -> Self {
        Self { y1, y2 }
    }

    /// Computes the statement from parameters and witness: `y1 = g^x`, `y2 = h^x`.
    pub fn from_witness(params: &Parameters, witness: &Witness) -> Self {
        let y1 = params.generator_g() * witness.secret();
        let y2 = params.generator_h() * witness.secret();
        Self { y1, y2 }
    }

    pub fn y1(&self) -> &Element {
        &self.y1
    }

    pub fn y2(&self) -> &Element {
        &self.y2
    }

    /// Checks that both values are valid, canonical group elements.
    pub fn validate(&self) -> Result<()> {
        self.y1.validate()?;
        self.y2.validate()?;
        Ok(())
    }
}

/// Commitment values in the Chaum-Pedersen proof.
///
/// First message from prover: `r1 = g^k`, `r2 = h^k` for random `k`.
#[derive(Clone, Debug)]
pub struct Commitment {
    r1: Element,
    r2: Element,
}

impl Commitment {
    pub fn new(r1: Element, r2: Element) -> Self {
        Self { r1, r2 }
    }

    pub fn r1(&self) -> &Element {
        &self.r1
    }

    pub fn r2(&self) -> &Element {
        &self.r2
    }
}

/// Response value in the Chaum-Pedersen proof.
///
/// Prover's response to challenge: `s = k + c*x`.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct Response {
    s: Scalar,
}

impl Response {
    pub fn new(s: Scalar) -> Self {
        Self { s }
    }

    pub fn s(&self) -> &Scalar {
        &self.s
    }
}

/// A complete non-interactive proof (commitment + response).
///
/// Single-use: bind each proof to a unique context via the transcript to prevent replay.
/// Serializes via [`Proof::to_bytes`] / [`Proof::from_bytes`].
#[derive(Clone, Debug)]
pub struct Proof {
    version: u8,
    commitment: Commitment,
    response: Response,
}

impl Proof {
    /// Assembles a proof from a commitment and response (usually via [`Prover`](crate::Prover)).
    pub fn new(commitment: Commitment, response: Response) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            commitment,
            response,
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    pub fn response(&self) -> &Response {
        &self.response
    }

    /// Serializes the proof to its versioned byte encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let r1_bytes = self.commitment.r1().to_bytes();
        let r2_bytes = self.commitment.r2().to_bytes();
        let s_bytes = self.response.s().to_bytes();

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

    /// Deserializes and validates a proof from its byte encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const MAX_ELEMENT_SIZE: usize = 4096;
        const MAX_SCALAR_SIZE: usize = 512;
        const MIN_PROOF_SIZE: usize = 1 + 4 + 1 + 4 + 1 + 4 + 1;

        if bytes.len() < MIN_PROOF_SIZE {
            return Err(Error::Deserialization);
        }

        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return Err(Error::Deserialization);
        }

        let mut pos = 1;

        if pos + 4 > bytes.len() {
            return Err(Error::Deserialization);
        }
        let r1_len = u32::from_be_bytes(
            bytes[pos..pos + 4]
                .try_into()
                .unwrap_or_else(|_| unreachable!("Slice is exactly 4 bytes")),
        ) as usize;
        pos += 4;

        if r1_len == 0 || r1_len > MAX_ELEMENT_SIZE {
            return Err(Error::Deserialization);
        }

        if pos + r1_len > bytes.len() {
            return Err(Error::Deserialization);
        }
        let r1 = Element::from_bytes(&bytes[pos..pos + r1_len])?;
        pos += r1_len;

        if pos + 4 > bytes.len() {
            return Err(Error::Deserialization);
        }
        let r2_len = u32::from_be_bytes(
            bytes[pos..pos + 4]
                .try_into()
                .unwrap_or_else(|_| unreachable!("Slice is exactly 4 bytes")),
        ) as usize;
        pos += 4;

        if r2_len == 0 || r2_len > MAX_ELEMENT_SIZE {
            return Err(Error::Deserialization);
        }

        if pos + r2_len > bytes.len() {
            return Err(Error::Deserialization);
        }
        let r2 = Element::from_bytes(&bytes[pos..pos + r2_len])?;
        pos += r2_len;

        if pos + 4 > bytes.len() {
            return Err(Error::Deserialization);
        }
        let s_len = u32::from_be_bytes(
            bytes[pos..pos + 4]
                .try_into()
                .unwrap_or_else(|_| unreachable!("Slice is exactly 4 bytes")),
        ) as usize;
        pos += 4;

        if s_len == 0 || s_len > MAX_SCALAR_SIZE {
            return Err(Error::Deserialization);
        }

        if pos + s_len > bytes.len() {
            return Err(Error::Deserialization);
        }
        let s = Scalar::from_bytes(&bytes[pos..pos + s_len])?;
        pos += s_len;

        if pos != bytes.len() {
            return Err(Error::Deserialization);
        }

        r1.validate()?;
        r2.validate()?;

        if r1.is_identity() || r2.is_identity() {
            return Err(Error::IdentityElement);
        }

        if s.is_zero() {
            return Err(Error::Deserialization);
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
    use crate::OsRng;

    #[test]
    fn parameters_default() {
        let params = Parameters::default();
        assert_eq!(params.generator_g(), &Element::generator_g());
        assert_eq!(params.generator_h(), &Element::generator_h());
    }

    #[test]
    fn parameters_rejects_identity_generators() {
        let identity = Element::identity();
        let g = Element::generator_g();

        assert!(Parameters::with_generators(identity.clone(), g.clone()).is_err());
        assert!(Parameters::with_generators(g.clone(), identity).is_err());
    }

    #[test]
    fn parameters_rejects_equal_generators() {
        let g = Element::generator_g();
        assert!(Parameters::with_generators(g.clone(), g).is_err());
    }

    #[test]
    fn statement_from_witness() {
        let mut rng = OsRng;
        let params = Parameters::new();
        let x = Scalar::random(&mut rng);
        let witness = Witness::new(x.clone());

        let statement = Statement::from_witness(&params, &witness);
        let expected_y1 = params.generator_g() * &x;
        let expected_y2 = params.generator_h() * &x;

        assert_eq!(statement.y1(), &expected_y1);
        assert_eq!(statement.y2(), &expected_y2);
    }

    #[test]
    fn proof_serialization() {
        let mut rng = OsRng;
        let r1 = &Element::generator_g() * &Scalar::random(&mut rng);
        let r2 = &Element::generator_h() * &Scalar::random(&mut rng);
        let commitment = Commitment::new(r1, r2);
        let response = Response::new(Scalar::random(&mut rng));
        let proof = Proof::new(commitment, response);

        let bytes = proof.to_bytes().unwrap();
        let deserialized = Proof::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.version(), PROTOCOL_VERSION);
    }

    #[test]
    fn proof_from_bytes_rejects_empty() {
        let result = Proof::from_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_truncated() {
        let result = Proof::from_bytes(&[1, 0, 0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_wrong_version() {
        let mut bytes = vec![99];
        bytes.extend_from_slice(&[0, 0, 0, 32]);
        bytes.resize(100, 0);
        let result = Proof::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_zero_length_fields() {
        let mut bytes = vec![PROTOCOL_VERSION];
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let result = Proof::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_excessive_length() {
        let mut bytes = vec![PROTOCOL_VERSION];
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let result = Proof::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_trailing_data() {
        let mut rng = OsRng;
        let r1 = &Element::generator_g() * &Scalar::random(&mut rng);
        let r2 = &Element::generator_h() * &Scalar::random(&mut rng);
        let commitment = Commitment::new(r1, r2);
        let response = Response::new(Scalar::random(&mut rng));
        let proof = Proof::new(commitment, response);

        let mut bytes = proof.to_bytes().unwrap();
        bytes.push(0xFF);

        let result = Proof::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_identity_commitment() {
        let identity = Element::identity();
        let mut rng = OsRng;
        let r2 = &Element::generator_h() * &Scalar::random(&mut rng);

        let commitment = Commitment::new(identity, r2);
        let response = Response::new(Scalar::random(&mut rng));
        let proof = Proof::new(commitment, response);

        let bytes = proof.to_bytes().unwrap();
        let result = Proof::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_zero_response() {
        let mut rng = OsRng;
        let r1 = &Element::generator_g() * &Scalar::random(&mut rng);
        let r2 = &Element::generator_h() * &Scalar::random(&mut rng);
        let commitment = Commitment::new(r1, r2);

        let zero_scalar = Scalar::from_bytes(&[0u8; 32]).unwrap();
        let response = Response::new(zero_scalar);
        let proof = Proof::new(commitment, response);

        let bytes = proof.to_bytes().unwrap();
        let result = Proof::from_bytes(&bytes);
        assert!(result.is_err());
    }
}
