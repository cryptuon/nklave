[![CI](https://github.com/cryptuon/nklave/actions/workflows/ci.yml/badge.svg)](https://github.com/cryptuon/nklave/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docs](https://img.shields.io/badge/docs-cryptuon.com-blue)](https://docs.cryptuon.com/nklave)
[![Crates.io](https://img.shields.io/crates/v/nklave-core.svg)](https://crates.io/crates/nklave-core)

# nklave

**[🌐 Site](https://nklave.cryptuon.com/) · [📚 Docs](https://docs.cryptuon.com/nklave/) · [📦 crates.io package](https://crates.io/crates/nklave-core) · [🔬 Cryptuon Research](https://github.com/cryptuon)**

**Policy-enforcing trust boundary for PoS validators.**

Nklave is a signing security layer that makes slashable signing impossible by construction. It sits between validator clients and signing keys, enforcing slashing-prevention rules before any signature is produced.

```
┌─────────────────┐         ┌─────────────────────────────────┐         ┌─────────────────┐
│ Validator Client│         │            Nklave               │         │  Signing Keys   │
│                 │  Sign   │  ┌───────────────────────────┐  │         │                 │
│  - Lighthouse   │ ──────▶ │  │     Policy Engine         │  │ ──────▶ │  - BLS (ETH2)   │
│  - Teku         │         │  │  ┌─────────────────────┐  │  │         │  - Ed25519      │
│  - Prysm        │ ◀────── │  │  │ Slashing Protection │  │  │ ◀────── │    (Cosmos)     │
│  - Lodestar     │  Sig/   │  │  └─────────────────────┘  │  │  Sign   │                 │
│                 │  Refuse │  └───────────────────────────┘  │         │                 │
└─────────────────┘         └─────────────────────────────────┘         └─────────────────┘
                                         │
                                         ▼
                            ┌───────────────────────┐
                            │   Append-Only Log     │
                            │   + Checkpoints       │
                            └───────────────────────┘
```

## Quick Start

### Docker

```bash
docker run -p 9000:9000 ghcr.io/cryptuon/nklave
```

### From Source

```bash
cargo install nklave-server
nklave --keys-dir ./keys --data-dir ./data
```

### With Docker Compose

```bash
git clone https://github.com/cryptuon/nklave
cd nklave
docker compose -f docker/docker-compose.yml up
```

## Features

- **Web3Signer Compatible** - Drop-in replacement for existing validator setups
- **Slashing Protection** - Enforces EIP-3076 and custom rules at the signing layer
- **Multi-Chain** - Ethereum (BLS), Cosmos/CometBFT (Ed25519), extensible to others
- **Audit Trail** - Append-only decision logs with cryptographic chaining
- **State Integrity** - Rollback-resistant checkpoints prevent state manipulation
- **Embedded UI** - Vue.js dashboard for monitoring and operations
- **High Availability** - Primary/passive replication with automatic failover

## Crates

| Crate | Description |
|-------|-------------|
| [`nklave-core`](crates/nklave-core) | Core signing logic, BLS/Ed25519 keys, slashing protection rules |
| [`nklave-api`](crates/nklave-api) | Web3Signer-compatible HTTP API with embedded UI |
| [`nklave-storage`](crates/nklave-storage) | Append-only logs, checkpoints, EIP-3076 interchange |
| [`nklave-server`](crates/nklave-server) | Main server binary with TLS, metrics, configuration |
| [`nklave-cosmos`](crates/nklave-cosmos) | Cosmos/CometBFT remote signer protocol |
| [`nklave-cli`](crates/nklave-cli) | CLI tools for key management and operations |

## API Endpoints

```bash
# Health checks
GET  /livez                          # Liveness probe
GET  /readyz                         # Readiness probe
GET  /health                         # Detailed health status

# Web3Signer API
GET  /api/v1/eth2/publicKeys         # List validator public keys
POST /api/v1/eth2/sign/:pubkey       # Sign a message

# Admin
POST /reload                         # Reload keys from disk
GET  /status                         # Server status
POST /admin/checkpoint               # Force checkpoint
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NKLAVE_LISTEN_ADDR` | `127.0.0.1:9000` | Server listen address |
| `NKLAVE_KEYS_DIR` | `./keys` | Validator keystores directory |
| `NKLAVE_DATA_DIR` | `./data` | State and logs directory |
| `NKLAVE_KEYSTORE_PASSWORD` | - | Password for encrypted keystores |
| `NKLAVE_API_TOKENS` | - | Comma-separated bearer tokens |
| `NKLAVE_METRICS_ADDR` | - | Prometheus metrics endpoint |
| `RUST_LOG` | `nklave=info` | Log level |

## Documentation

Full documentation at [docs.cryptuon.com/nklave](https://docs.cryptuon.com/nklave):

- [Architecture](https://docs.cryptuon.com/nklave/architecture)
- [Deployment Guide](https://docs.cryptuon.com/nklave/deployment)
- [Threat Model](https://docs.cryptuon.com/nklave/threat-model)
- [Slashing Policy](https://docs.cryptuon.com/nklave/slashing-policy)
- [API Reference](https://docs.cryptuon.com/nklave/api)

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes before submitting a PR.

```bash
# Run tests
cargo test --all

# Run with coverage
cargo llvm-cov --all-features

# Run benchmarks
cargo bench -p nklave-core
```

## License

MIT License - [Cryptuon Research](https://www.cryptuon.com) · [contact@cryptuon.com](mailto:contact@cryptuon.com)

---

## Part of Cryptuon Research

`nklave` is one of [20 open-source blockchain-infrastructure projects](https://www.cryptuon.com/projects) from **[Cryptuon Research](https://www.cryptuon.com)** — blockchain theory, shipped as protocols.

**Related projects:** [Tesseract](https://tesseract.cryptuon.com/) · [Switchboard](https://switchboard.cryptuon.com/) · [StreamSync](https://streamsync.cryptuon.com/)

Docs: [docs.cryptuon.com/nklave](https://docs.cryptuon.com/nklave/) · Contact: [contact@cryptuon.com](mailto:contact@cryptuon.com)
