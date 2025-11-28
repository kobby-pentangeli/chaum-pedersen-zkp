# Chaum-Pedersen Zero-Knowledge Protocol

[![Crates.io](https://img.shields.io/crates/v/chaum-pedersen-zkp.svg)](https://crates.io/crates/chaum-pedersen-zkp)
[![Documentation](https://docs.rs/chaum-pedersen-zkp/badge.svg)](https://docs.rs/chaum-pedersen-zkp)
[![CI](https://github.com/kobby-pentangeli/chaum-pedersen-zkp/workflows/CI/badge.svg)](https://github.com/kobby-pentangeli/chaum-pedersen-zkp/actions)
[![License](https://img.shields.io/crates/l/chaum-pedersen-zkp.svg)](https://github.com/kobby-pentangeli/chaum-pedersen-zkp#license)

Rust implementation of the Chaum-Pedersen Zero-Knowledge Proof protocol for password-based authentication without storing passwords.

## Overview

This implementation allows a **prover (client)** to demonstrate knowledge of a secret discrete logarithm `x` such that `y1 = g^x` and `y2 = h^x` without revealing `x` to the **verifier (server)**. The server never stores passwords, only public statements (y1, y2).

**Key Features:**

- **Zero-knowledge authentication**: Server never sees passwords
- **High performance**: 0.14ms proof generation, 0.16ms verification
- **Batch verification**: 30-50% faster for verifying multiple proofs simultaneously
- **Constant-time operations**: Protection against timing attacks
- **Memory zeroization**: Automatic clearing of sensitive data
- **gRPC API**: Server with TLS, rate limiting, metrics
- **Ristretto255**: Fast, prime-order elliptic curve with ~128-bit security

## TODO

- [x] **Security Audit**

## Architecture

```txt
src/
├── primitives/        # Core cryptographic primitives
│   ├── ristretto.rs   # Ristretto255 group implementation
│   ├── rng.rs         # Secure random number generator
│   ├── gadgets.rs     # Parameters, Statement, Witness, Proof
│   └── transcript.rs  # Fiat-Shamir transform
├── prover/            # Client-side proof generation
├── verifier/          # Server-side proof verification
│   ├── config.rs      # Configuration with .env support
│   ├── service.rs     # gRPC service implementation
│   ├── batch.rs       # Batch verification
│   └── state.rs       # Server state management
└── bin/
    ├── client.rs      # Interactive CLI client (prover)
    └── server.rs      # Interactive gRPC server (verifier)
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

The server provides an interactive REPL for monitoring and management while handling gRPC requests.

**Start the server:**

```bash
cargo run --release --bin server --features server
```

**With custom options:**

```bash
cargo run --release --bin server --features server -- \
  --host 0.0.0.0 \
  --port 50051 \
  --rate-limit 100 \
  --rate-burst 50 \
  --metrics
```

**Server REPL commands:**

```sh
+---------------------------------------------------------+
|       Chaum-Pedersen ZKP Authentication Server          |
+---------------------------------------------------------+

Server starting on 127.0.0.1:50051
  Rate limit: 100 req/min, burst: 50
  Metrics: disabled
  Health check: enabled

Type /help for available commands or /quit to exit

zkp-server@127.0.0.1:50051> /help

Available Commands:

  /status              - Show server status and configuration
  /users               - List registered users count
  /sessions            - List active sessions count
  /challenges          - List pending challenges count
  /cleanup             - Force cleanup of expired state
  /help                - Show this help message
  /quit or /exit       - Initiate graceful shutdown
```

**Environment variables (optional):**

```bash
SERVER_HOST=127.0.0.1                    # Bind address
SERVER_PORT=50051                        # gRPC port
METRICS_ENABLED=true                     # Enable Prometheus metrics
METRICS_PORT=9090                        # Metrics endpoint port
RATE_LIMIT_RPM=100                       # Requests per minute
RATE_LIMIT_BURST=50                      # Burst capacity
```

### Run Client (Prover)

The client provides an interactive REPL for registration and authentication.

**Start the client:**

```bash
cargo run --release --bin client --features client
```

**Connect to custom server:**

```bash
cargo run --release --bin client --features client -- --server http://192.168.1.100:50051
```

**Client REPL commands:**

```sh
+---------------------------------------------------------+
|       Chaum-Pedersen ZKP Authentication Client          |
+---------------------------------------------------------+

Connecting to http://127.0.0.1:50051...
Connected successfully

Type /help for available commands or /quit to exit

zkp-client@http://127.0.0.1:50051> /help

Available Commands:

  /register <user> <pass>              - Register a new user
  /login <user> <pass>                 - Authenticate (prove knowledge of password)
  /batch-register <u1,u2> <p1,p2>      - Batch register multiple users
  /batch-login <u1,u2> <p1,p2>         - Batch authenticate multiple users
  /status                              - Show connection status
  /help                                - Show this help message
  /quit or /exit                       - Exit gracefully

Examples:
  /register alice secretpass123
  /login alice secretpass123
  /batch-register alice,bob pass1,pass2
  /batch-login alice,bob pass1,pass2
```

**Example session:**

```sh
zkp-client@http://127.0.0.1:50051> /register alice mypassword
Registered: User 'alice' registered

zkp-client@http://127.0.0.1:50051> /login alice mypassword
  Challenge received, expires: 1732409876
Authenticated: Proof verified successfully
  Session token: a1b2c3d4e5f6...

zkp-client@http://127.0.0.1:50051> /batch-register bob,charlie pass1,pass2
Registering 2 users...
  [OK] bob: User 'bob' registered
  [OK] charlie: User 'charlie' registered
Batch complete: 2/2 registered

zkp-client@http://127.0.0.1:50051> /quit

Goodbye!
```

## Development

```bash
# Format with `rustfmt.toml`
cargo +nightly fmt

# Linting
cargo clippy --all-targets --all-features

# Testing
cargo test --all-features

# Testing with progress output (useful for long-running batch tests)
cargo test --all-features -- --nocapture

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
    Ristretto255, SecureRng, Parameters, Witness, Statement,
    Prover, Verifier, Transcript
};

// Setup parameters
let params = Parameters::new();
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
use chaum_pedersen::Proof;

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
let mut batch_verifier = BatchVerifier::new();

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

## Feature Flags

```toml
[features]
default = []
grpc = ["tonic", "prost", "tokio"]           # gRPC support
server = ["grpc", "tonic-health", "tower", "metrics", "crossterm", "clap", "tracing"]
client = ["grpc", "clap", "argon2", "crossterm", "tracing"]
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
- [merlin](https://github.com/dalek-cryptography/merlin) - Fiat-Shamir transcripts
- [tonic](https://github.com/hyperium/tonic) - gRPC framework
- [argon2](https://github.com/RustCrypto/password-hashes) - Password hashing
- [crossterm](https://github.com/crossterm-rs/crossterm) - Terminal colors and formatting
