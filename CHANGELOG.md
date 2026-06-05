# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-06-05

Closes soundness gaps, hardens performance claims with more accurate measured numbers, simplifies the proof encoding, and hardens the gRPC server. This release is **breaking** since 1.0.0---both the public API and the wire format change, and the domain-separation tags are de-versioned, so every persisted statement, registration, and credential must be regenerated.

### Breaking changes and migration

- **Proof wire format.** Proofs are now a fixed `version ‖ r1 ‖ r2 ‖ s` layout of **97 bytes** (was a length-prefixed encoding of 109 bytes), exposed as `Proof::SIZE`. The version byte is bumped `1 --> 2`, so a 1.0.0 parser rejects a 1.1.0 proof on the version byte. `Proof::to_bytes` now returns `[u8; Proof::SIZE]` (was `Result<Vec<u8>>`).
- **De-versioned domain tags (one-time, regenerate everything).** The generator-`h` domain tag, the Merlin protocol label, and the client's Argon2 salt prefix no longer embed a release version; they are rebuilt from a single `CIPHERSUITE = "chaum-pedersen-zkp/ristretto255"` base. This changes the second generator `h`, every Fiat-Shamir challenge, and every password-derived key---**existing registrations and credentials stop verifying and must be re-created.**
- **Fallible constructors.** `Statement::new` and `Witness::new` now return `Result` (they reject identity statements and the zero witness). `Statement::from_witness` and `Prover::new` stay infallible.
- **Removed surface.** The `Ristretto255` free-function struct and the `SecureRng` wrapper are gone; use the operator API / inherent methods on `Scalar` and `Element`, and the re-exported `OsRng`.
- **gRPC API additions (breaking proto).** Two new RPCs---`ValidateSession` and `Logout`---plus `SessionRequest` / `SessionResponse` / `LogoutResponse` messages.

### Added

- **Operator API on `Scalar` / `Element`**: `Add`/`Sub`/`Mul`/`Neg` (with ref/assign variants) and inherent `random` / `to_bytes` / `from_bytes` / generator / validation methods; `generator_h` memoized with `LazyLock`.
- **Centralized domain module** (`primitives::domain`): all domain-separation tags, built from one `CIPHERSUITE` base; `CIPHERSUITE` is re-exported.
- **Real multi-scalar-multiplication batch verification**: one randomized combined equation with two independent weights per proof, a shared-generator collapse, and a variable-time MSM; falls back to individual verification to localize failures.
- **Session lifecycle**: `ValidateSession` (authenticated endpoint) and `Logout` (idempotent revoke) RPCs, backed by `ServerState::validate_session` / `revoke_session`; the client REPL gains `/whoami` and `/logout`.
- **Per-peer rate limiting**: token buckets keyed by gRPC peer IP, with bounded eviction of idle buckets.

### Changed

- **Typed errors**: `Error` is seven precise, allocation-free variants; server-state failures moved to a dedicated `StateError`.
- **Dependencies modernized**: gRPC stack to the 0.14 line (`tonic` / `tonic-prost` / `prost` / `tonic-health`), `criterion` 0.8, `metrics-exporter-prometheus` 0.18; MSRV raised to 1.88; Rust 2024 edition.
- **Single-proof verification** now uses a variable-time multi-scalar multiplication on the public verification data (was constant-time scalar multiplication).
- **Server cleanup task** flattened from a spawn-inside-spawn-inside-loop to a single `tokio::spawn` with one interval loop.
- **Tightened gRPC bounds** to exact sizes (`y1`/`y2` --> 32, proof --> `Proof::SIZE`, `challenge_id` --> 32).
- **Server configuration consolidated onto clap** (CLI flags + `.env` via dotenvy), with all server env vars uniformly `SERVER_`-prefixed (`SERVER_RATE_LIMIT_RPM`, `SERVER_RATE_LIMIT_BURST`, `SERVER_METRICS_ENABLED`, `SERVER_METRICS_PORT`). The unused figment `ServerConfig` / `config/server.toml` layer and the never-wired TLS configuration were removed (real TLS termination is deferred); `.env` is now loaded before argument parsing so it actually takes effect.

### Fixed

- **Batch verification was mathematically wrong in 1.0.0** (it weighted `r1` but not `y1` by the random coefficient), so the fast path never held and every batch silently fell through to slower individual verification. Reimplemented correctly.
- **Soundness gaps**: identity statement/commitment elements and a zero challenge are now rejected on the verify path; the verifier validates the commitment, not only the statement.
- Stale generated `src/auth.rs` no longer written into the source tree (`build.rs` emits to `OUT_DIR`); both fuzz targets compile again.

### Security

- Zeroization restricted to the genuinely secret `Witness` / `Nonce`; the public `Response` / `Commitment` are no longer zeroized, and the deprecated `#[zeroize(drop)]` is removed.
- Registration deliberately requires no proof of possession (a forged statement is useless without `x`; possession is proved at authentication).

### Performance

Measured on a `32GB RAM MacOS Apple M1 Max` machine (`cargo bench`); reproduce locally before quoting.

- Proof generation: ~144 µs
- Proof verification: ~118 µs (single proof; was ~159 µs constant-time)
- Statement serialization / deserialization: ~7.5 µs / ~23 µs
- Proof size: 97 bytes (was 109)
- Batch verification: faster than individual at every batch size, from ≈26% at 1 proof to ≈59% at 100

---

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

[1.1.0]: https://github.com/kobby-pentangeli/chaum-pedersen-zkp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/kobby-pentangeli/chaum-pedersen-zkp/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/kobby-pentangeli/chaum-pedersen-zkp/releases/tag/v0.1.0
