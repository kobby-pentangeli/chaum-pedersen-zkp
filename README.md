# The Chaum-Pedersen Protocol

The Chaum-Pedersen Zero-Knowledge protocol is a cryptographic algorithm that allows a prover to convince a verifier that they possess a secret value without revealing the value itself.

## References

1. [Original Chaum-Pedersen Protocol Paper](https://link.springer.com/content/pdf/10.1007/3-540-48071-4_7.pdf)
2. [RFC 5114 (for predefined group parameters)](https://www.rfc-editor.org/rfc/rfc5114#section-2)

## Disclaimer

This implementation is still work-in-progress. Please do not deploy in production.

## Usage

To use this Rust implementation of the Chaum-Pedersen ZKP protocol, please follow these steps:

1. Clone the repository:

```bash
git clone https://github.com/kobby-pentangeli/chaum-pedersen-zkp.git
cd chaum-pedersen-zkp
```

2. Run the server:

```bash
cargo run --bin server
```

3. In a separate terminal instance, run the client:

```bash
cargo run --bin client
```

4. Follow the prompts.

## Contributing

Thank you for considering to contribute to this project!

All contributions large and small are actively accepted.

* To get started, please read the [contribution guidelines](https://github.com/kobby-pentangeli/chaum-pedersen-zkp/blob/master/CONTRIBUTING.md).

* Browse [Good First Issues](https://github.com/kobby-pentangeli/chaum-pedersen-zkp/labels/good%20first%20issue).
