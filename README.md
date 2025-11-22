# Chaum-Pedersen Zero-Knowledge Protocol

[![Crates.io](https://img.shields.io/crates/v/chaum-pedersen-zkp.svg)](https://crates.io/crates/chaum-pedersen-zkp)
[![Documentation](https://docs.rs/chaum-pedersen-zkp/badge.svg)](https://docs.rs/chaum-pedersen-zkp)
[![CI](https://github.com/kobby-pentangeli/chaum-pedersen-zkp/workflows/CI/badge.svg)](https://github.com/kobby-pentangeli/chaum-pedersen-zkp/actions)
[![License](https://img.shields.io/crates/l/chaum-pedersen-zkp.svg)](https://github.com/kobby-pentangeli/chaum-pedersen-zkp#license)

Rust implementation of the Chaum-Pedersen Zero-Knowledge Proof protocol for password-based authentication without storing passwords.

## Overview

This implementation allows a **prover (client)** to demonstrate knowledge of a secret discrete logarithm `x` such that `y1 = g^x` and `y2 = h^x` without revealing `x` to the **verifier (server)**. The server never stores passwords—only public statements (y1, y2).

**Key Features:**

- **Zero-knowledge authentication**: Server never sees passwords
- **High performance**: 0.14ms proof generation, 0.16ms verification (Ristretto255)
- **Batch verification**: 30-50% faster for verifying multiple proofs simultaneously
- **Constant-time operations**: Protection against timing attacks
- **Memory zeroization**: Automatic clearing of sensitive data
- **gRPC API**: Server with TLS, rate limiting, metrics
- **Multiple groups**: Ristretto255 (recommended),  P-256, and RFC 5114 MODP

## Architecture

```txt
src/
├── primitives/        # Core cryptographic primitives
│   ├── crypto/        # Field operations, group trait, secure RNG
│   ├── groups/        # Ristretto255, P-256, RFC5114 implementations
│   ├── gadgets.rs     # Parameters, Statement, Witness, Proof
│   └── transcript.rs  # Fiat-Shamir transform
├── prover/            # Client-side proof generation
├── verifier/          # Server-side proof verification
│   ├── config.rs      # Configuration with .env support
│   ├── service.rs     # gRPC service implementation
│   └── state.rs       # Server state management
└── bin/
    ├── client.rs      # CLI client (prover)
    └── server.rs      # gRPC server (verifier)
```

## Quick Start

### Prerequisites

**Required:**

- Rust 1.85+ ([install](https://rustup.rs/))
- Protocol Buffers compiler (`protoc`)

**Install protoc:**

```bash
# macOS
brew install protobuf

# Ubuntu/Debian
sudo apt-get install protobuf-compiler

# Arch Linux
sudo pacman -S protobuf

# Windows
choco install protoc
```

### Build

```bash
# Clone repository
git clone https://github.com/kobby-pentangeli/chaum-pedersen-zkp.git
cd chaum-pedersen-zkp

# Build all features (server + client)
cargo build --release --all-features

# Build library only
cargo build --release

# Build server only
cargo build --release --bin server --features server

# Build client only
cargo build --release --bin client --features client
```

### Run Examples

**Basic protocol usage:**

```bash
cargo run --example hello_world
```

**Authentication system simulation:**

```bash
cargo run --example auth_system
```

### Run Server (Verifier)

**1. Configure (optional):**

The server automatically loads configuration from multiple sources (priority order):

1. Environment variables (highest)
2. TOML file (`config/server.toml`)
3. `.env` file (auto-loaded)
4. Built-in defaults (lowest)

```bash
# Option 1: Use .env file (easiest - automatically loaded)
cp .env.example .env
# Edit .env with your settings

# Option 2: Use TOML config
cp config/server.toml.example config/server.toml
# Edit config/server.toml

# Option 3: Environment variables directly
export SERVER_HOST=0.0.0.0
export SERVER_PORT=50051
```

**Available configuration:**

```bash
# Network
SERVER_HOST=127.0.0.1                    # Bind address
SERVER_PORT=50051                        # gRPC port

# Rate limiting (token bucket)
SERVER_RATE_LIMIT_REQUESTS_PER_MINUTE=60 # Sustained rate
SERVER_RATE_LIMIT_BURST=10               # Burst capacity

# Metrics (Prometheus)
SERVER_METRICS_ENABLED=true              # Enable/disable
SERVER_METRICS_PORT=9090                 # Metrics endpoint

# TLS
SERVER_TLS_ENABLED=false                 # Enable TLS
SERVER_TLS_CERT_PATH=/path/to/cert.pem   # Certificate
SERVER_TLS_KEY_PATH=/path/to/key.pem     # Private key
```

**2. Run:**

```bash
cargo run --release --bin server --features server
```

### Run Client (Prover)

**Register user:**

```bash
cargo run --release --bin client --features client -- register \
  --user alice \
  --password secret123
```

**Batch register (multiple users):**

```bash
cargo run --release --bin client --features client -- batch-register \
  --users alice,bob,charlie \
  --passwords password1,password2,password3
```

Registers multiple users in a single request, reducing network overhead.

**Authenticate (individual):**

```bash
cargo run --release --bin client --features client -- login \
  --user alice \
  --password secret123
```

**Batch authenticate (multiple users):**

```bash
cargo run --release --bin client --features client -- batch-login \
  --users alice,bob,charlie \
  --passwords password1,password2,password3
```

This uses batch verification on the server, providing 30-50% better performance compared to individual logins.

**Custom server:**

```bash
cargo run --release --bin client --features client -- \
  --server http://192.168.1.100:50051 \
  login --user alice --password secret123
```

## Development

```bash
# Format with `rustfmt.toml`
cargo +nightly fmt

# Linting
cargo clippy --all-targets --all-features

# Testing
cargo test --all-features

# Benchmarking
# Run all benchmarks
cargo bench

# Specific benchmark
cargo bench ristretto_proof_generation

# Fuzzing
# Install fuzzer (requires nightly)
cargo install cargo-fuzz

# Fuzz proof deserialization
cargo +nightly fuzz run fuzz_proof_deserialization

# Run for 10 minutes
cargo +nightly fuzz run fuzz_proof_deserialization -- -max_total_time=600

# Use multiple cores
cargo +nightly fuzz run fuzz_proof_deserialization -- -jobs=4
```

## Library Usage

### Basic Example

```rust
use chaum_pedersen::{
    Ristretto255, Group, SecureRng, Parameters, Witness, Statement,
    Prover, Verifier, Transcript
};

// Setup parameters
let params = Parameters::<Ristretto255>::new();
let mut rng = SecureRng::new();

// Prover: Generate secret and create statement
let x = Ristretto255::random_scalar(&mut rng);
let witness = Witness::new(x);
let statement = Statement::from_witness(&params, &witness);

// Prover: Generate proof (Fiat-Shamir)
let mut transcript = Transcript::new();
let proof = Prover::new(params.clone(), witness)
    .prove_with_transcript(&mut rng, &mut transcript)
    .unwrap();

// Verifier: Verify the proof
let mut verify_transcript = Transcript::new();
let verifier = Verifier::new(params, statement);
assert!(verifier.verify_with_transcript(&proof, &mut verify_transcript).is_ok());
```

### Interactive Protocol

```rust
// Prover: Commitment phase
let prover = Prover::new(params.clone(), witness);
let (commitment, nonce) = prover.commit(&mut rng);

// Verifier: Challenge (can be sent over network)
let challenge = Ristretto255::random_scalar(&mut rng);

// Prover: Response phase
let response = prover.respond(&nonce, &challenge);
let proof = Proof::new(commitment, response);

// Verifier: Verification
let verifier = Verifier::new(params, statement);
assert!(verifier.verify_response(&challenge, &proof).is_ok());
```

### Batch Verification

Batch verification provides 30-50% better performance when verifying multiple proofs:

```rust
use chaum_pedersen::BatchVerifier;

// Create batch verifier
let mut batch_verifier = BatchVerifier::<Ristretto255>::new();

// Add multiple proofs to batch
for i in 0..10 {
    let x = Ristretto255::random_scalar(&mut rng);
    let witness = Witness::new(x);
    let prover = Prover::new(params.clone(), witness);
    let statement = prover.statement().clone();

    let mut transcript = Transcript::new();
    transcript.append_context(format!("user-{}", i).as_bytes());
    let proof = prover.prove_with_transcript(&mut rng, &mut transcript).unwrap();

    // Add to batch with context binding
    batch_verifier.add_with_context(
        params.clone(),
        statement,
        proof,
        Some(format!("user-{}", i).into_bytes())
    ).unwrap();
}

// Verify entire batch at once (single multi-scalar multiplication)
let results = batch_verifier.verify(&mut rng).unwrap();

// Check individual results
for (i, result) in results.iter().enumerate() {
    assert!(result.is_ok(), "Proof {} should be valid", i);
}
```

### Group Selection

**Ristretto255 (Recommended):**

- 100x faster than RFC5114
- Smaller proofs (~109 bytes)
- Prime-order group
- Security: ~128-bit

**RFC5114 (Legacy):**

- NIST-standardized (deprecated)
- Slower performance
- Larger proofs (~512 bytes)
- Security: ~112-bit

```rust
use chaum_pedersen::{Rfc5114, P256, Ristretto255};

// Use Ristretto255 (recommended)
let params = Parameters::<Ristretto255>::new();

// Or RFC5114 for legacy compatibility
let params = Parameters::<Rfc5114>::new();

// Or P-256 (experimental)
let params = Parameters::<P256>::new();
```

## Feature Flags

```toml
[features]
default = []
grpc = ["tonic", "prost", "tokio"]           # gRPC support
server = ["grpc", "tonic-health", "tower", "metrics", "dotenvy"]
client = ["grpc", "clap", "argon2"]
```

**Build examples:**

```bash
# Library only (no network)
cargo build

# Server with gRPC
cargo build --features server

# Client with gRPC
cargo build --features client

# Both
cargo build --all-features
```

## References

- [Original Chaum-Pedersen Paper](https://link.springer.com/content/pdf/10.1007/3-540-48071-4_7.pdf)
- [RFC 5114 - MODP Groups](https://www.rfc-editor.org/rfc/rfc5114#section-2)
- [RFC 8247 - Deprecation of RFC 5114](https://www.rfc-editor.org/rfc/rfc8247.html)
- [Ristretto255 Specification](https://ristretto.group/)

## Contributing

Contributions welcome! Please:

1. Read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
2. Run tests: `cargo test --all-features`
3. Run clippy: `cargo clippy --all-features -- -D warnings`
4. Format code: `cargo +nightly fmt`

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Acknowledgments

Built with:

- [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) - Ristretto255 group operations
- [crypto-bigint](https://github.com/RustCrypto/crypto-bigint) - Constant-time big integers
- [merlin](https://github.com/dalek-cryptography/merlin) - Fiat-Shamir transcripts
- [tonic](https://github.com/hyperium/tonic) - gRPC framework
- [argon2](https://github.com/RustCrypto/password-hashes) - Password hashing
