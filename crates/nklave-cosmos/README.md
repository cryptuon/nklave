# nklave-cosmos

[![Crates.io](https://img.shields.io/crates/v/nklave-cosmos.svg)](https://crates.io/crates/nklave-cosmos)
[![Docs.rs](https://docs.rs/nklave-cosmos/badge.svg)](https://docs.rs/nklave-cosmos)

Cosmos/CometBFT remote signer protocol (Tendermint PrivValidator) for [Nklave](https://github.com/cryptuon/nklave).

## Features

- **PrivValidator Protocol** - Compatible with CometBFT's remote signer interface
- **Ed25519 Signing** - Native Cosmos validator key support
- **Double Sign Prevention** - Height/round-based slashing protection
- **gRPC Interface** - Tendermint protobuf message handling

## Usage

```rust
use nklave_cosmos::{CosmosSigningService, Ed25519Keypair};

let keypair = Ed25519Keypair::generate();
let service = CosmosSigningService::new(keypair);

// Sign a vote
let signature = service.sign_vote(&vote_request)?;
```

## Supported Message Types

- `SignVoteRequest` - Block votes (prevote, precommit)
- `SignProposalRequest` - Block proposals
- `PubKeyRequest` - Public key queries

## License

MIT License - [Cryptuon](https://cryptuon.com)
