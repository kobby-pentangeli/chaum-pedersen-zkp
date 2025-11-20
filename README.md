# The Chaum-Pedersen Protocol

The Chaum-Pedersen Zero-Knowledge protocol is a cryptographic algorithm that allows a prover to convince a verifier that they possess a secret value without revealing the value itself.

## References

1. [Original Chaum-Pedersen Protocol Paper](https://link.springer.com/content/pdf/10.1007/3-540-48071-4_7.pdf)
2. [RFC 5114 (for predefined group parameters)](https://www.rfc-editor.org/rfc/rfc5114#section-2)

## Disclaimer

This implementation is still work-in-progress. Please do not deploy in production.

## Prerequisites

### Build Dependencies

This project requires the Protocol Buffers compiler (`protoc`) for building the gRPC service definitions.

**macOS:**

```bash
brew install protobuf
```

**Ubuntu/Debian:**

```bash
sudo apt-get install protobuf-compiler
```

**Arch Linux:**

```bash
sudo pacman -S protobuf
```

**Windows:**
Download from [GitHub releases](https://github.com/protocolbuffers/protobuf/releases) or use:

```powershell
choco install protoc
```

### Rust Toolchain

- Rust 1.85 or later
- Cargo (comes with Rust)

## Usage

To use this Rust implementation of the Chaum-Pedersen ZKP protocol, please follow these steps:

1. Clone the repository:

```bash
git clone https://github.com/kobby-pentangeli/chaum-pedersen-zkp.git
cd chaum-pedersen-zkp
```

2. Build the project (this will compile protobuf definitions):

```bash
cargo build --release --all-features
```

3. Configure the server (optional):

```bash
# Option 1: Copy and edit TOML configuration file
cp config/server.toml.example config/server.toml
# Edit config/server.toml with your settings

# Option 2: Use environment variables
cp .env.example .env
# Edit .env with your settings
# Then: export $(cat .env | xargs)

# Option 3: Set environment variables directly
export SERVER_HOST=0.0.0.0
export SERVER_PORT=50051
```

4. Run the server:

```bash
cargo run --release --bin server --features server
```

5. In a separate terminal instance, register a user:

```bash
cargo run --release --bin client --features client -- register --user alice --password secret123
```

6. Authenticate the user:

```bash
cargo run --release --bin client --features client -- login --user alice --password secret123
```

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
