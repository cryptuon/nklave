# nklave-core

[![Crates.io](https://img.shields.io/crates/v/nklave-core.svg)](https://crates.io/crates/nklave-core)
[![Docs.rs](https://docs.rs/nklave-core/badge.svg)](https://docs.rs/nklave-core)

Core signing logic, BLS/Ed25519 keys, and slashing protection rules for [Nklave](https://github.com/cryptuon/nklave).

## Features

- **BLS Signatures** - Ethereum validator signing with slashing protection
- **Ed25519 Signatures** - Cosmos/CometBFT validator signing
- **Slashing Protection** - Enforces surround vote and double vote prevention
- **State Integrity** - Cryptographic chaining of signing decisions
- **Key Management** - EIP-2335 keystore support with encryption

## Usage

```rust
use nklave_core::{SigningService, BlsKeypair};

// Create a signing service with a keypair
let keypair = BlsKeypair::generate();
let service = SigningService::new(vec![keypair]);

// Sign an attestation (with slashing protection)
let result = service.sign_attestation(
    &pubkey,
    source_epoch,
    target_epoch,
    signing_root,
)?;
```

## Feature Flags

- `aws-kms` - Enable AWS KMS key provider support
- `vault` - Enable HashiCorp Vault key provider support

## License

MIT License - [Cryptuon](https://cryptuon.com)
