# Chaum-Pedersen Zero-Knowledge Protocol

## Overview

The Chaum-Pedersen protocol proves *equality of two discrete logarithms* in zero knowledge: given two generators `g` and `h` and two public values `y1 = g^x`, `y2 = h^x`, the prover convinces the verifier that it knows a single `x` satisfying both equations, without revealing `x`. It was introduced by David Chaum and Torben Pryds Pedersen in *Wallet Databases with Observers* (CRYPTO '92).

This implementation follows §3.2 ("The Basic Scheme") of that paper. The equation convention below---response `s = k + c·x`, verification `g^s = r1·y1^c`---is the one the code implements. We also present the algebraically equivalent *negated* form (`s' = k − c·x`, `r1 = g^{s'}·y1^c`); the two differ only in the sign of the response and verify identically.

## Group setting

The protocol runs in a cyclic group of prime order `ℓ`, written multiplicatively here. This implementation instantiates it with **Ristretto255**, a prime-order group built over Curve25519 with order

```txt
ℓ = 2^252 + 27742317777372353535851937790883648493
```

giving roughly 128-bit security. In the code the group law is point addition, so `g^x` denotes scalar multiplication of the point `g` by the scalar `x`, and exponents are scalars modulo `ℓ`. There is no modulus `p` and no `Z*_p`: Ristretto255 is already prime-order, so it needs no cofactor clearing or subgroup checks beyond canonical encoding validation.

The two generators are:

- **`g`** —-- the Ristretto255 basepoint.
- **`h`** —-- a second generator derived by hashing a fixed domain-separation tag (`chaum-pedersen-zkp/ristretto255/generator-h`) to the group. Deriving `h` this way is *nothing-up-my-sleeve*: no party knows `log_g(h)`, which is what makes `g` and `h` independent bases.

## Security properties

- **Completeness.** An honest prover that knows `x` always produces a proof the verifier accepts.
- **Special soundness.** From two accepting transcripts that share the same commitment `(r1, r2)` but use different challenges, `(c, s)` and `(c', s')` with `c ≠ c'`, one extracts the witness `x = (s − s')·(c − c')^{−1} mod ℓ`. This makes the interactive protocol a proof of knowledge with knowledge error `1/ℓ`. For a *false* statement (where `log_g(y1) ≠ log_h(y2)`) any commitment admits at most one satisfying challenge, so a cheating prover succeeds with probability at most `1/ℓ`---this bound holds against a computationally unbounded prover.
- **Honest-verifier zero-knowledge (HVZK).** Transcripts reveal nothing about `x`: a simulator that does not know `x` picks `c` and `s` uniformly at random and sets `r1 = g^s·y1^{−c}`, `r2 = h^s·y2^{−c}`, producing a transcript identically distributed to a real one. Zero knowledge here is *perfect*.

The non-interactive variant this project deploys (Fiat-Shamir, below) inherits these properties only in the **random oracle model (ROM)**: with the challenge derived from a concrete hash function, soundness and zero knowledge become assumptions about that hash behaving as a random oracle. They are *not* unconditional.

## Interactive protocol

The prover holds a secret `x ∈ Z_ℓ` and the public statement `(y1, y2) = (g^x, h^x)`. The protocol is a three-move Sigma protocol.

### 1. Commitment (prover --> verifier)

The prover samples a uniformly random nonce `k ∈ Z_ℓ`, computes

```txt
r1 = g^k
r2 = h^k
```

and sends `(r1, r2)`.

### 2. Challenge (verifier --> prover)

The verifier samples a uniformly random challenge `c ∈ Z_ℓ` and sends it. This implementation additionally rejects `c = 0`, which would collapse the `y^c` binding term to the identity.

### 3. Response (prover --> verifier)

The prover computes and sends

```txt
s = k + c·x   (mod ℓ)
```

### Verification

The verifier accepts if and only if both equations hold:

```txt
g^s = r1·y1^c
h^s = r2·y2^c
```

Correctness follows by substitution:

```txt
g^s = g^(k + c·x) = g^k·(g^x)^c = r1·y1^c
h^s = h^(k + c·x) = h^k·(h^x)^c = r2·y2^c
```

## Non-interactive variant (Fiat-Shamir)

The interactive protocol is made non-interactive by deriving the challenge from the transcript instead of from the verifier:

```txt
c = H(g, h, y1, y2, r1, r2, context)
```

This implementation realizes `H` with a Merlin transcript: the generators, statement, and commitment are absorbed in a fixed order under domain-separated labels, an optional caller-supplied `context` is bound in, and the challenge scalar is squeezed out. The proof is the triple `(r1, r2, s)`; the verifier recomputes `c` from the same transcript and checks the two equations. Binding the `context` makes a proof valid only for the exact session it was produced for.

## Interactive vs. deployed flow

The scheme in §3.2 of the original paper is interactive---the verifier contributes the randomness `c`. The library exposes both forms:

- **Interactive primitives** (`commit` / `respond` / `verify_response`) implement §3.2 faithfully and accept an externally supplied challenge.
- **Non-interactive prover/verifier** (`prove_with_transcript` / `verify_with_transcript`) implement the Fiat-Shamir form and are the default.

The gRPC authentication service uses the Fiat-Shamir flow, saving a round trip. Its `CreateChallenge` step issues a random, single-use `challenge_id` that is bound into the transcript as the `context`. It is a replay nonce, **not** the protocol challenge `c`, which is always `H(transcript)`. A strictly interactive deployment (server-sent random `c`) is possible but is not the chosen design.

## Batch verification

`N` proofs `(r1_i, r2_i, s_i)` for statements `(y1_i, y2_i)` with challenges `c_i` can be checked together far faster than one at a time. The verifier draws `2N` independent random weights `α_i, β_i ∈ Z_ℓ` and checks the single group equation

```txt
Σ_i [ α_i·s_i·g + β_i·s_i·h − α_i·r1_i − β_i·r2_i − α_i·c_i·y1_i − β_i·c_i·y2_i ] = O
```

where `O` is the identity. The `i`-th proof contributes `α_i·(g^{s_i}·y1_i^{−c_i}·r1_i^{−1}) + β_i·(h^{s_i}·y2_i^{−c_i}·r2_i^{−1})` (written additively above), which is `O` exactly when *both* of that proof's verification equations hold. When every entry shares the same `g` and `h` the two generator terms collapse to `(Σ α_i·s_i)·g + (Σ β_i·s_i)·h`, shrinking the combination from `6N` to `2 + 4N` terms. The whole sum is evaluated as one variable-time multi-scalar multiplication.

**Soundness.** Verification data is public, so a variable-time multi-scalar multiplication leaks nothing secret. If any proof is invalid, at least one of its two bracketed terms is non-identity; by the Schwartz-Zippel lemma the randomly weighted sum is `O` with probability at most `1/ℓ`. The *two* independent weights per proof are essential: a single shared weight would let a proof that satisfies only one of its two equations be masked by the other.

**Failure handling.** On a batch failure the verifier falls back to individual verification to report which proofs are invalid, and challenges are consumed atomically before verification to prevent races. Batches are capped (1000 proofs) to bound memory.

**Measured performance.** Batch verification is faster than the equivalent individual verifications at *every* batch size on a `32GB RAM MacOS Apple M1 Max` machine, widening from about 26% at `N = 1` to about 59% at `N = 100`. These numbers are machine-specific; run `cargo bench` to reproduce them locally.

## Security considerations

- **Nonce secrecy and uniqueness.** `k` must be sampled uniformly at random for every proof and never reused: two proofs sharing `k` under different challenges expose `x = (s − s')·(c − c')^{−1}`. The implementation samples `k` from the OS CSPRNG.
- **Independent generators.** `h` must have an unknown discrete log relative to `g`; it is derived by hashing a domain tag to the group for exactly this reason.
- **Timing.** Secret-dependent operations (sampling `k`, computing `s = k + c·x`) use constant-time scalar arithmetic. Verification deliberately uses variable-time multi-scalar multiplication; its inputs are entirely public, so data-dependent timing reveals nothing about any secret.
- **Statement and commitment validity.** Identity statement or commitment elements and a zero challenge are rejected; these degenerate inputs would otherwise admit trivially "known" secrets.

## Comparison with the Schnorr protocol

Chaum-Pedersen extends the Schnorr identification protocol. Schnorr proves knowledge of `x` with `y = g^x` over a single base; Chaum-Pedersen proves knowledge of one `x` satisfying `y1 = g^x` and `y2 = h^x` simultaneously, i.e. equality of discrete logs across two bases. Both are three-move Sigma protocols with special soundness and HVZK, require only a small constant number of group operations, and compose into proofs of more complex statements about discrete logarithms.

## References

1. Chaum, D., & Pedersen, T. P. (1992). *Wallet Databases with Observers.* In Advances in Cryptology —-- CRYPTO '92 (pp. 89-105). Springer. [DOI: 10.1007/3-540-48071-4_7](https://doi.org/10.1007/3-540-48071-4_7). §3.2 is the authority for this implementation.
2. Ristretto255: a prime-order group abstraction over Curve25519. [ristretto.group](https://ristretto.group/).
3. Schnorr, C. P. (1991). *Efficient Signature Generation by Smart Cards.* Journal of Cryptology, 4(3), 161-174.

## Notation

| Symbol   | Meaning                                                |
| -------- | ------------------------------------------------------ |
| `ℓ`      | Prime order of the Ristretto255 group                  |
| `Z_ℓ`    | Scalars modulo `ℓ` (the exponent field)                |
| `g, h`   | Independent generators (`g` = basepoint, `h` = hashed) |
| `x`      | Prover's secret (the shared discrete logarithm)        |
| `y1, y2` | Public statement, `y1 = g^x`, `y2 = h^x`               |
| `k`      | Prover's random nonce                                  |
| `r1, r2` | Commitment, `r1 = g^k`, `r2 = h^k`                     |
| `c`      | Challenge (random, or `H(transcript)` in Fiat-Shamir)  |
| `s`      | Response, `s = k + c·x`                                |
| `α, β`   | Random batch-verification weights                      |
