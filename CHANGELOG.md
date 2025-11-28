# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-28

First major release of the Chaum-Pedersen zero-knowledge proof protocol implementation.

### Added

#### Core Protocol

- **Ristretto255 Group Operations**: Prime-order elliptic curve with ~128-bit security using curve25519-dalek
- **Prover Implementation**: Commitment generation (r1 = g^k, r2 = h^k) and response computation (s = k + c*x)
- **Verifier Implementation**: Verification equations (g^s == r1 *y1^c, h^s == r2* y2^c)
- **Fiat-Shamir Transform**: Non-interactive proofs via Merlin transcript with domain separation
- **Batch Verification**: 30-50% performance improvement for 10+ proofs using randomized batch equations
- **Wide Scalar Reduction**: 64-byte hash-to-scalar via `from_bytes_mod_order_wide` for uniform distribution
- **Deterministic Generator Derivation**: Hash-to-curve with domain separation for independent generators

#### Cryptographic Primitives

- **Secure RNG**: Wrapper around OsRng for cryptographic randomness
- **Memory Zeroization**: Automatic secret clearing for Witness, Nonce, Response, and Scalar types
- **Constant-Time Operations**: Timing attack resistance via subtle crate and ct_eq
- **Proof Serialization**: Versioned binary format with comprehensive validation
- **Input Validation**: Identity element rejection, bounds checking, canonical encoding verification

#### Client-Server Infrastructure

- **Interactive REPL Client**: Async CLI with colored terminal output, commands: `/register`, `/login`, `/batch-register`, `/batch-login`, `/status`, `/help`, `/quit`
- **Interactive REPL Server**: Async server with commands: `/status`, `/users`, `/sessions`, `/challenges`, `/quit`
- **gRPC Service**: Full authentication flow with batch operations (register, challenge, verify)
- **Password-Based Auth**: Argon2id hashing with SHA-256 salt derivation and SHA-512 scalar derivation
- **State Management**: Thread-safe (Arc<RwLock>) user registry, challenge tracking, session management
- **Graceful Shutdown**: Ctrl+C handling, phased shutdown, proper terminal state restoration

#### Security Features

- **DoS Mitigation**: Token bucket rate limiting (configurable), size limits (user ID: 256, proof: 8192, batch: 1000)
- **Resource Caps**: 10k users, 50k challenges, 100k sessions, 3 challenges/user, 5 sessions/user
- **Replay Protection**: Single-use challenges with 5min expiry, context binding via transcript
- **Challenge Expiry**: 5-minute TTL with 2x max age check for clock skew tolerance
- **Session Expiry**: 1-hour TTL with automatic cleanup every 60 seconds
- **Input Validation**: Comprehensive bounds checking, malformed proof rejection
- **Information Hiding**: Generic error messages ("Authentication failed") prevent oracle attacks

#### Testing

- **81 Tests Total**:
  - 44 unit tests (primitives, gadgets, proof serialization)
  - 11 integration tests (full gRPC auth flow, batch operations)
  - 8 security tests (replay attacks, identity detection, proof corruption)
  - 5 property tests (proof validity invariants)
  - 13 doc tests
- **Benchmarks**: Proof generation (~144μs), verification (~159μs), batch verification
- **Fuzzing Targets**: Proof deserialization, statement validation
- **Test Coverage**: All critical paths covered including error cases

#### Documentation

- **Protocol Specification** (`docs/protocol.md`): Mathematical description, security analysis, implementation notes
- **Comprehensive README**: Quick start, installation, examples, architecture overview
- **API Documentation**: Doc comments on all public APIs with security notes and examples
- **Examples**:
  - `hello_world.rs` - Basic protocol usage
  - `auth_system.rs` - Authentication system simulation
  - `batch_verification.rs` - Batch verification demonstration

#### Configuration

- **Server Config Builder**: TOML file support with validation and sensible defaults
- **Environment Variables**: `.env` file loading for `host`, `port`, rate limiting, metrics
- **Feature Flags**: Modular builds (`server`, `client`, `metrics`)
- **Tunable Parameters**:
  - Challenge expiry: 300s default
  - Session expiry: 3600s default
  - Rate limit: 100 req/min default, burst: 50
  - Cleanup interval: 60s default

#### CI/CD

- **GitHub Actions Workflows**: Multi-platform testing (Linux, macOS, Windows)
- **Security Audits**: Automated vulnerability scanning with cargo-audit
- **Caching**: Dependency and build caching for faster CI
- **CODEOWNERS**: Automatic review assignment

### Changed

#### Rust Edition

- Upgraded from 2021 to 2024 Edition
- Set minimum supported Rust version: 1.85

#### Dependencies

- `curve25519-dalek` 4.x - Ristretto255 operations
- `merlin` 3.0 - Fiat-Shamir transcripts
- `zeroize` 1.7 - Memory zeroization
- `subtle` 2.6 - Constant-time comparisons
- `tonic` 0.12 - gRPC framework (server feature)
- `tokio` 1.x - Async runtime (server/client features)
- `argon2` 0.5 - Password hashing (client feature)
- `crossterm` 0.29 - Terminal colors (server/client features)

### Performance

- Proof generation: ~144μs
- Proof verification: ~159μs
- Proof size: 109 bytes
- Batch verification: 30-50% faster for 10+ proofs
- Serialization overhead: ~7μs

---

## [0.1.0] - Prior to production implementation

Initial project skeleton before v1.0.0 rewrite.

[1.0.0]: https://github.com/kobby-pentangeli/chaum-pedersen-zkp/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/kobby-pentangeli/chaum-pedersen-zkp/releases/tag/v0.1.0
