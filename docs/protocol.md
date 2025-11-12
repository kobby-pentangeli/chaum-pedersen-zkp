# Chaum-Pedersen Zero-Knowledge Protocol

## Overview

The Chaum-Pedersen protocol is a zero-knowledge proof system that allows a prover to convince a verifier that they know a discrete logarithm without revealing the secret value itself. Specifically, it proves knowledge of a value `x` such that for two generators `g` and `h`, the prover knows `x` where `y1 = g^x` and `y2 = h^x`, effectively proving equality of discrete logarithms across different bases.

This protocol was introduced by David Chaum and Torben Pryds Pedersen in their 1992 CRYPTO paper "Wallet Databases with Observers."

## Mathematical Foundation

### Parameters

The protocol operates over a cyclic group `G` of prime order `q`. The public parameters are:

- **p**: A large prime number (the modulus)
- **q**: A prime dividing `p - 1` (the order of the subgroup)
- **g**: A generator of the subgroup of order `q` in Z*_p
- **h**: Another generator of the same subgroup (where `h = g^i` for some `i`)

### Security Properties

1. **Completeness**: If both parties follow the protocol honestly, the verifier will always accept a valid proof
2. **Soundness**: A malicious prover cannot convince the verifier of a false statement except with negligible probability
3. **Zero-Knowledge**: The verifier learns nothing about the secret `x` beyond the fact that the prover knows it

## Protocol Description

### Setup Phase

The prover possesses a secret value `x` in Z_q and computes:

- `y1 = g^x mod p`
- `y2 = h^x mod p`

The values `(y1, y2)` are made public, while `x` remains secret.

### Interactive Protocol

The protocol proceeds in three rounds (commitment, challenge, response):

#### 1. Commitment (Prover -> Verifier)

The prover:

1. Chooses a random value `k` in Z_q
2. Computes commitments:
   - `r1 = g^k mod p`
   - `r2 = h^k mod p`
3. Sends `(r1, r2)` to the verifier

#### 2. Challenge (Verifier -> Prover)

The verifier:

1. Chooses a random challenge `c` in Z_q
2. Sends `c` to the prover

#### 3. Response (Prover -> Verifier)

The prover:

1. Computes the response: `s = k - c*x mod q`
2. Sends `s` to the verifier

### Verification

The verifier accepts the proof if and only if both of the following equations hold:

```sh
r1 = g^s * y1^c (mod p)
r2 = h^s * y2^c (mod p)
```

#### Verification Correctness

The verification works because:

```sh
g^s * y1^c = g^(k - c*x) * (g^x)^c = g^k * g^(-c*x) * g^(c*x) = g^k = r1
h^s * y2^c = h^(k - c*x) * (h^x)^c = h^k * h^(-c*x) * h^(c*x) = h^k = r2
```

## Non-Interactive Variant (Fiat-Shamir Transform)

The interactive protocol can be made non-interactive using the Fiat-Shamir heuristic:

1. The prover computes `c = H(g, h, y1, y2, r1, r2)` where `H` is a cryptographic hash function
2. The proof consists of `(r1, r2, s)` or equivalently `(c, s)`
3. The verifier recomputes the challenge from the hash and verifies the proof

This eliminates the need for interaction and produces a signature of knowledge.

## Security Considerations

### Randomness Requirements

- The value `k` must be chosen uniformly at random from Z_q for each proof
- **Critical**: Never reuse `k` across multiple proofs, as this would leak the secret `x`

### Challenge Space

- The challenge `c` should be drawn from a sufficiently large space to prevent brute-force attacks
- For computational soundness, `c` typically ranges over Z_q

### Parameter Selection

- The prime `p` should be at least 2048 bits for security (3072 bits recommended)
- The order `q` should be at least 256 bits
- Use standardized groups (e.g., RFC 5114) or generate parameters provably

### Timing Attacks

- Implementation must use constant-time operations for modular arithmetic
- The computation of `s` should not leak information about `x` through timing channels

## Applications

The Chaum-Pedersen protocol is used in various cryptographic applications:

1. **Authentication Systems**: Proving knowledge of a password without transmitting it
2. **Electronic Voting**: Proving correct decryption of encrypted votes
3. **Blockchain and Cryptocurrencies**: Privacy-preserving transaction proofs
4. **Anonymous Credentials**: Proving possession of attributes without revealing identity
5. **Secure Multi-Party Computation**: Proving correct behavior in distributed protocols

## Comparison with Related Protocols

### Schnorr Protocol

The Chaum-Pedersen protocol is an extension of the Schnorr identification protocol. While Schnorr proves knowledge of `x` such that `y = g^x`, Chaum-Pedersen proves knowledge of a single `x` such that `y1 = g^x` and `y2 = h^x` simultaneously.

### Advantages

- **Unconditional Soundness**: Cannot be broken even with unlimited computational power
- **Efficient**: Requires only a small constant number of exponentiations
- **Composable**: Can be extended to prove more complex statements about discrete logarithms
- **Well-Studied**: Has been analyzed extensively in the cryptographic literature

## Implementation Notes

### Modular Arithmetic

All computations are performed modulo `p` for group elements and modulo `q` for exponents:

- Group operations: `(g^a * g^b) mod p = g^(a+b) mod p`
- Exponent arithmetic: `(a + b) mod q`

### Negative Exponents

When computing `s = k - c*x mod q`, if `k < c*x`, the result must be computed as:

```sh
s = q - ((c*x - k) mod q)
```

This ensures `s` is always a positive value in Z_q.

### Verification Optimization

The verification equations can be computed efficiently using:

- Simultaneous multi-exponentiation algorithms
- Pre-computation of fixed-base exponentiations for `g` and `h`

## References

1. **Original Paper**: Chaum, D., & Pedersen, T. P. (1992). "Wallet Databases with Observers." In *Advances in Cryptology -- CRYPTO '92* (pp. 89-105). Springer. [DOI: 10.1007/3-540-48071-4_7](https://doi.org/10.1007/3-540-48071-4_7)

2. **RFC 5114**: "Additional Diffie-Hellman Groups for Use with IETF Standards" - Provides standardized group parameters. [View RFC 5114](https://www.rfc-editor.org/rfc/rfc5114)

3. **Schnorr, C. P.** (1991). "Efficient Signature Generation by Smart Cards." *Journal of Cryptology*, 4(3), 161-174.

4. **Camenisch, J., & Stadler, M.** (1997). "Proof Systems for General Statements about Discrete Logarithms." Technical Report, ETH Zurich.

## Notation Summary

| Symbol   | Meaning                                     |
| -------- | ------------------------------------------- |
| `p`      | Large prime modulus                         |
| `q`      | Prime order of subgroup (divides `p - 1`)   |
| `g, h`   | Generators of the subgroup of order `q`     |
| `x`      | Prover's secret value                       |
| `y1, y2` | Public values computed from secret `x`      |
| `k`      | Prover's random commitment value            |
| `r1, r2` | Commitment values sent to verifier          |
| `c`      | Challenge chosen by verifier                |
| `s`      | Response computed by prover                 |
| `Z_q`    | Integers modulo `q`                         |
| `Z*_p`   | Multiplicative group of integers modulo `p` |

---

**Note**: This document provides a user-centric description of the Chaum-Pedersen protocol. For implementation details and security proofs, please refer to the original academic paper and modern cryptographic standards.
