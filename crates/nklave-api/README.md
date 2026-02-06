# nklave-api

[![Crates.io](https://img.shields.io/crates/v/nklave-api.svg)](https://crates.io/crates/nklave-api)
[![Docs.rs](https://docs.rs/nklave-api/badge.svg)](https://docs.rs/nklave-api)

Web3Signer-compatible HTTP API with embedded UI for [Nklave](https://github.com/cryptuon/nklave).

## Features

- **Web3Signer Compatible** - Drop-in replacement for existing validator setups
- **Embedded UI** - Vue.js dashboard compiled into the binary
- **Authentication** - Bearer token and mTLS support
- **Authorization** - Role-based access control (read, sign, admin)

## Endpoints

```
GET  /api/v1/eth2/publicKeys         # List validator public keys
POST /api/v1/eth2/sign/:pubkey       # Sign a message
GET  /health                         # Health status
GET  /livez                          # Liveness probe
GET  /readyz                         # Readiness probe
POST /reload                         # Reload keys from disk
```

## Usage

```rust
use nklave_api::{create_router_with_ui, AppState, ApiConfig};
use std::sync::Arc;

let state = Arc::new(AppState::new(signing_service));
let router = create_router_with_ui(state, ApiConfig::default());
```

## License

MIT License - [Cryptuon](https://cryptuon.com)
