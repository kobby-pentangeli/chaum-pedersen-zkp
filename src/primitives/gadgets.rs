//! Core protocol data structures: parameters, witness, statement, commitment, response, proof.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{Element, Scalar};
use crate::{Error, Result};

const PROTOCOL_VERSION: u8 = 2;

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
    ///
    /// Rejects the zero scalar: `x = 0` yields the identity statement `y1 = y2 = identity`, a
    /// trivially-known "secret" that destroys soundness.
    pub fn new(x: Scalar) -> Result<Self> {
        if x.is_zero() {
            return Err(Error::IdentityElement);
        }
        Ok(Self { x })
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
    /// Wraps two group elements as a statement after checking both are canonical, non-identity
    /// encodings (see [`Statement::validate`]).
    pub fn new(y1: Element, y2: Element) -> Result<Self> {
        let statement = Self { y1, y2 };
        statement.validate()?;
        Ok(statement)
    }

    /// Computes the statement from parameters and witness: `y1 = g^x`, `y2 = h^x`.
    ///
    /// Infallible: [`Witness`] guarantees `x != 0`, so neither `y1` nor `y2` is the identity.
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

    /// Checks that both values are canonical, non-identity group elements.
    ///
    /// An identity `y1` or `y2` corresponds to the discrete log `x = 0` and is rejected.
    pub fn validate(&self) -> Result<()> {
        self.y1.validate()?;
        self.y2.validate()?;

        if self.y1.is_identity() || self.y2.is_identity() {
            return Err(Error::IdentityElement);
        }

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

    /// Checks that both commitment values are canonical, non-identity group elements.
    ///
    /// An identity `r1` or `r2` lets a malicious prover sidestep the binding check, so it is
    /// rejected on the verification path, not only at deserialization.
    pub fn validate(&self) -> Result<()> {
        self.r1.validate()?;
        self.r2.validate()?;

        if self.r1.is_identity() || self.r2.is_identity() {
            return Err(Error::IdentityElement);
        }

        Ok(())
    }
}

/// Response value in the Chaum-Pedersen proof.
///
/// Prover's response to challenge: `s = k + c*x`. Public (part of the transmitted proof), so it is
/// not zeroized.
#[derive(Clone, Debug)]
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
    /// Wire size of a serialized proof: a 1-byte version tag followed by the fixed 32-byte
    /// encodings of `r1`, `r2`, and `s`.
    pub const SIZE: usize = 1 + 3 * 32;

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

    /// Serializes the proof to its fixed [`Self::SIZE`]-byte encoding `version ‖ r1 ‖ r2 ‖ s`.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0] = self.version;
        bytes[1..33].copy_from_slice(&self.commitment.r1().to_bytes());
        bytes[33..65].copy_from_slice(&self.commitment.r2().to_bytes());
        bytes[65..97].copy_from_slice(&self.response.s().to_bytes());
        bytes
    }

    /// Deserializes and validates a proof from its fixed [`Self::SIZE`]-byte encoding.
    ///
    /// Rejects any input that is not exactly [`Self::SIZE`] bytes, carries the wrong version, fails
    /// to decode as canonical group/scalar values, or violates the soundness invariants (identity
    /// `r1`/`r2`, zero `s`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; Self::SIZE] = bytes.try_into().map_err(|_| Error::Deserialization)?;

        if bytes[0] != PROTOCOL_VERSION {
            return Err(Error::Deserialization);
        }

        let commitment = Commitment::new(
            Element::from_bytes(&bytes[1..33])?,
            Element::from_bytes(&bytes[33..65])?,
        );
        commitment.validate()?;

        let s = Scalar::from_bytes(&bytes[65..97])?;
        if s.is_zero() {
            return Err(Error::Deserialization);
        }

        Ok(Proof {
            version: bytes[0],
            commitment,
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
        let witness = Witness::new(x.clone()).unwrap();

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

        let bytes = proof.to_bytes();
        let deserialized = Proof::from_bytes(&bytes).unwrap();

        assert_eq!(bytes.len(), Proof::SIZE);
        assert_eq!(deserialized.version(), PROTOCOL_VERSION);
    }

    #[test]
    fn proof_from_bytes_rejects_empty() {
        let result = Proof::from_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_wrong_length() {
        assert!(Proof::from_bytes(&[PROTOCOL_VERSION; Proof::SIZE - 1]).is_err());
        assert!(Proof::from_bytes(&[PROTOCOL_VERSION; Proof::SIZE + 1]).is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_wrong_version() {
        let mut rng = OsRng;
        let r1 = &Element::generator_g() * &Scalar::random(&mut rng);
        let r2 = &Element::generator_h() * &Scalar::random(&mut rng);
        let commitment = Commitment::new(r1, r2);
        let response = Response::new(Scalar::random(&mut rng));
        let proof = Proof::new(commitment, response);

        let mut bytes = proof.to_bytes();
        bytes[0] = PROTOCOL_VERSION.wrapping_add(1);
        assert!(Proof::from_bytes(&bytes).is_err());
    }

    #[test]
    fn proof_from_bytes_rejects_trailing_data() {
        let mut rng = OsRng;
        let r1 = &Element::generator_g() * &Scalar::random(&mut rng);
        let r2 = &Element::generator_h() * &Scalar::random(&mut rng);
        let commitment = Commitment::new(r1, r2);
        let response = Response::new(Scalar::random(&mut rng));
        let proof = Proof::new(commitment, response);

        let mut bytes = proof.to_bytes().to_vec();
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

        let bytes = proof.to_bytes();
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

        let bytes = proof.to_bytes();
        let result = Proof::from_bytes(&bytes);
        assert!(result.is_err());
    }
}
